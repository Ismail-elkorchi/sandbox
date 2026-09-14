#![cfg(windows)]

use sandsurf_protocol::{Counter, Resources};
use sandsurf_state::{CatalogLimits, Error, HostCatalog};

#[test]
fn unimplemented_windows_private_state_cannot_be_mistaken_for_secure_storage() {
    let one = Counter::ONE;
    let path =
        std::env::temp_dir().join(format!("sandsurf-unqualified-state-{}", std::process::id()));
    let result = HostCatalog::create(
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
    );
    assert!(matches!(result, Err(Error::Unsupported(_))));
    assert!(!path.exists());
}
