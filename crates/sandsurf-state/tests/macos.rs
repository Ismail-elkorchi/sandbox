#![cfg(target_os = "macos")]

use sandsurf_protocol::{Counter, Resources};
use sandsurf_state::{CatalogLimits, HostCatalog};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::process::Command;

#[test]
fn macos_acl_grants_make_authority_unavailable_without_repair_or_deletion() {
    let root = std::env::temp_dir().join(format!(
        "sandsurf-acl-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let catalog = root.join("catalog");
    let one = Counter::ONE;
    let limits = CatalogLimits {
        identities: one,
        operations: one,
        grants: one,
        usage_records: one,
        image_bytes: one,
        resources: Resources {
            vcpus: one,
            memory_mib: one,
            disk_bytes: one,
            output_bytes: one,
            processes: one,
        },
    };
    drop(HostCatalog::create(&catalog, "acl-host".try_into().unwrap(), limits).unwrap());
    for (path, grant) in [
        (
            catalog.join("authority.sqlite"),
            "everyone allow read,write",
        ),
        (catalog.join("writer.lock"), "everyone allow read,write"),
        (catalog.clone(), "everyone allow list,search"),
    ] {
        let before = fs::read(catalog.join("authority.sqlite")).unwrap();
        assert!(
            Command::new("/bin/chmod")
                .args(["+a", grant])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let mode = fs::metadata(&path).unwrap().mode() & 0o077;
        let opened = HostCatalog::open(&catalog);
        // Inspect the ACL itself: rejected admission must not quietly remove it.
        let still_granted = Command::new("/bin/ls")
            .arg("-lde")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            Command::new("/bin/chmod")
                .arg("-N")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(mode, 0);
        assert!(opened.is_err());
        assert!(still_granted.status.success());
        assert!(
            String::from_utf8(still_granted.stdout)
                .unwrap()
                .contains("everyone allow")
        );
        assert_eq!(fs::read(catalog.join("authority.sqlite")).unwrap(), before);
        drop(HostCatalog::open(&catalog).unwrap());
    }
    fs::remove_dir_all(&root).unwrap();
}
