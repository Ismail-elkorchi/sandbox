#![cfg(unix)]

use sandsurf_protocol::*;
use sandsurf_state::*;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

fn n(value: u64) -> Counter {
    value.try_into().unwrap()
}
fn limits() -> RuntimeLimits {
    RuntimeLimits {
        identities: n(8),
        operations: n(8),
        observations: n(8),
        chunks: n(8),
        pins: n(8),
        output_bytes: n(1024),
        disks: n(8),
        disk_bytes: n(512 * 1024),
        disk_headroom_bytes: n(1024 * 1024),
    }
}
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sandsurf-disks-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn source(&self, name: &str, bytes: &[u8]) -> File {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.0.join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        file
    }
    fn runtime(&self) -> RuntimeJournal {
        RuntimeJournal::create(&self.0.join("runtime"), "box".try_into().unwrap(), limits())
            .unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn request(name: &str, bytes: &[u8]) -> DiskCopy {
    DiskCopy {
        id: name.try_into().unwrap(),
        operation_id: format!("copy-{name}").try_into().unwrap(),
        source_digest: bytes_digest(bytes),
        bytes: n(bytes.len() as u64),
        purpose: DiskPurpose::Workload,
    }
}

#[test]
fn raw_copy_is_reserved_verified_independent_and_persistent() {
    let root = Root::new();
    let bytes: Vec<u8> = (0..256 * 1024).map(|v| (v % 251) as u8).collect();
    let source = root.source("base", &bytes);
    let mut runtime = root.runtime();
    let a = runtime.prepare_disk_copy(request("a", &bytes)).unwrap();
    let b = runtime.prepare_disk_copy(request("b", &bytes)).unwrap();
    assert!(
        runtime
            .acquire_disk(&a.request.id, &a.request_digest)
            .is_err()
    );
    for record in [&a, &b] {
        assert_eq!(
            runtime
                .materialize_disk(&record.request.id, &record.request_digest, &source)
                .unwrap()
                .phase,
            DiskPhase::Ready
        );
    }
    let attachment = runtime
        .acquire_disk(&a.request.id, &a.request_digest)
        .unwrap();
    let handle = attachment.duplicate_handle().unwrap();
    assert!(handle.metadata().unwrap().blocks() * 512 >= bytes.len() as u64);
    handle.write_all_at(b"installed package", 0).unwrap();
    attachment.flush_host().unwrap();
    assert!(
        runtime
            .acquire_disk(&a.request.id, &a.request_digest)
            .is_err()
    );
    drop(attachment);
    // Duplicating a descriptor keeps the same exclusive attachment lease alive.
    assert!(
        runtime
            .acquire_disk(&a.request.id, &a.request_digest)
            .is_err()
    );
    drop(handle);
    drop(runtime);
    let runtime =
        RuntimeJournal::open(&root.0.join("runtime"), &"box".try_into().unwrap()).unwrap();
    let a = runtime
        .acquire_disk(&a.request.id, &a.request_digest)
        .unwrap()
        .duplicate_handle()
        .unwrap();
    let b = runtime
        .acquire_disk(&b.request.id, &b.request_digest)
        .unwrap()
        .duplicate_handle()
        .unwrap();
    let mut actual = vec![0; bytes.len()];
    b.read_exact_at(&mut actual, 0).unwrap();
    assert_eq!(actual, bytes);
    source.read_exact_at(&mut actual, 0).unwrap();
    assert_eq!(actual, bytes);
    let mut installed = [0; 17];
    a.read_exact_at(&mut installed, 0).unwrap();
    assert_eq!(&installed, b"installed package");
}

#[test]
fn invalid_or_interrupted_copy_never_becomes_attachable() {
    let root = Root::new();
    let bytes = vec![23; 256 * 1024];
    let source = root.source("base", &bytes);
    let wrong = root.source("corrupt", &vec![19; bytes.len()]);
    let mut runtime = root.runtime();
    let record = runtime
        .prepare_disk_copy(request("recover", &bytes))
        .unwrap();
    assert!(
        runtime
            .materialize_disk(&record.request.id, &record.request_digest, &wrong)
            .is_err()
    );
    assert_eq!(
        runtime.disk(&record.request.id).unwrap().unwrap().phase,
        DiskPhase::Copying
    );
    assert!(
        runtime
            .acquire_disk(&record.request.id, &record.request_digest)
            .is_err()
    );
    let own_partial = File::open(root.0.join("runtime/disk-recover.raw")).unwrap();
    assert!(
        runtime
            .materialize_disk(&record.request.id, &record.request_digest, &own_partial)
            .is_err()
    );
    assert_eq!(own_partial.metadata().unwrap().len(), bytes.len() as u64);
    drop(runtime);
    let mut runtime =
        RuntimeJournal::open(&root.0.join("runtime"), &"box".try_into().unwrap()).unwrap();
    assert_eq!(
        runtime.prepare_disk_copy(record.request.clone()).unwrap(),
        record
    );
    let ready = runtime
        .materialize_disk(&record.request.id, &record.request_digest, &source)
        .unwrap();
    assert_eq!(ready.phase, DiskPhase::Ready);
    // A retry must never overwrite an already published, potentially guest-mutated disk.
    let held = runtime
        .acquire_disk(&record.request.id, &record.request_digest)
        .unwrap();
    held.duplicate_handle()
        .unwrap()
        .write_all_at(b"mutable", 0)
        .unwrap();
    assert_eq!(
        runtime
            .materialize_disk(&record.request.id, &record.request_digest, &wrong)
            .unwrap(),
        ready
    );
    let mut actual = [0; 7];
    held.duplicate_handle()
        .unwrap()
        .read_exact_at(&mut actual, 0)
        .unwrap();
    assert_eq!(&actual, b"mutable");
}

#[test]
fn retirement_gates_attachments_and_holds_reservation_until_cleanup() {
    let root = Root::new();
    let bytes = vec![3; 512 * 1024];
    let source = root.source("base", &bytes);
    let mut runtime = root.runtime();
    let record = runtime.prepare_disk_copy(request("owned", &bytes)).unwrap();
    runtime
        .materialize_disk(&record.request.id, &record.request_digest, &source)
        .unwrap();
    let held = runtime
        .acquire_disk(&record.request.id, &record.request_digest)
        .unwrap();
    assert!(
        runtime
            .cleanup_disk(&record.request.id, &record.request_digest)
            .is_err()
    );
    runtime
        .retire_disk(&record.request.id, &record.request_digest)
        .unwrap();
    assert!(
        runtime
            .acquire_disk(&record.request.id, &record.request_digest)
            .is_err()
    );
    assert!(
        runtime
            .cleanup_disk(&record.request.id, &record.request_digest)
            .is_err()
    );
    assert!(
        runtime
            .prepare_disk_copy(request("replacement", &bytes))
            .is_err()
    );
    drop(held);
    let deleted = runtime
        .cleanup_disk(&record.request.id, &record.request_digest)
        .unwrap();
    assert_eq!(deleted.phase, DiskPhase::Deleted);
    assert!(deleted.cleanup_digest.is_some());
    assert!(!root.0.join("runtime/disk-owned.raw").exists());
    assert_eq!(
        runtime.prepare_disk_copy(record.request.clone()).unwrap(),
        deleted
    );
    assert_eq!(
        runtime
            .cleanup_disk(&record.request.id, &record.request_digest)
            .unwrap(),
        deleted
    );
    runtime
        .prepare_disk_copy(request("replacement", &bytes))
        .unwrap();
    assert!(
        runtime
            .materialize_disk(&record.request.id, &record.request_digest, &source)
            .is_err()
    );
}

#[test]
fn identity_conflicts_and_impossible_headroom_do_not_publish_or_evict() {
    let root = Root::new();
    let bytes = vec![42; 4096];
    let source = root.source("base", &bytes);
    let mut bounded = limits();
    bounded.disk_headroom_bytes = n(Counter::MAX);
    let mut runtime =
        RuntimeJournal::create(&root.0.join("runtime"), "box".try_into().unwrap(), bounded)
            .unwrap();
    let record = runtime
        .prepare_disk_copy(request("reserved", &bytes))
        .unwrap();
    let mut conflict = record.request.clone();
    conflict.source_digest = bytes_digest(b"wrong");
    assert!(runtime.prepare_disk_copy(conflict).is_err());
    assert!(
        runtime
            .materialize_disk(&record.request.id, &record.request_digest, &source)
            .is_err()
    );
    assert_eq!(
        runtime.disk(&record.request.id).unwrap(),
        Some(record.clone())
    );
    assert!(
        runtime
            .acquire_disk(&record.request.id, &record.request_digest)
            .is_err()
    );
    assert!(
        runtime
            .retire_disk(&record.request.id, &bytes_digest(b"wrong"))
            .is_err()
    );
    assert_eq!(source.metadata().unwrap().len(), bytes.len() as u64);
}

#[test]
fn abrupt_disk_writer_child() {
    let Some(path) = std::env::var_os("SANDSURF_DISK_CRASH_ROOT") else {
        return;
    };
    let path = PathBuf::from(path);
    let stage = std::env::var("SANDSURF_DISK_CRASH_STAGE").unwrap();
    let bytes = vec![7; 65536];
    let source = File::open(path.join("base")).unwrap();
    let mut runtime =
        RuntimeJournal::create(&path.join("runtime"), "box".try_into().unwrap(), limits()).unwrap();
    let record = runtime.prepare_disk_copy(request("crash", &bytes)).unwrap();
    if stage == "intent" {
        std::process::exit(61);
    }
    runtime
        .materialize_disk(&record.request.id, &record.request_digest, &source)
        .unwrap();
    if stage == "ready" {
        std::process::exit(61);
    }
    runtime
        .retire_disk(&record.request.id, &record.request_digest)
        .unwrap();
    if stage == "unlink" {
        fs::remove_file(path.join("runtime/disk-crash.raw")).unwrap();
    }
    std::process::exit(61);
}

#[test]
fn corrupted_disk_metadata_cannot_change_copy_or_deletion_scope() {
    for corrupt in [
        "UPDATE disks SET request=json_set(request,'$.bytes',512)",
        "UPDATE disks SET request=json_set(request,'$.id','other')",
        "UPDATE disks SET cleanup_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
    ] {
        let root = Root::new();
        let bytes = vec![42; 4096];
        let source = root.source("base", &bytes);
        let mut runtime = root.runtime();
        let record = runtime.prepare_disk_copy(request("bound", &bytes)).unwrap();
        runtime
            .materialize_disk(&record.request.id, &record.request_digest, &source)
            .unwrap();
        drop(runtime);
        let db = rusqlite::Connection::open(root.0.join("runtime/authority.sqlite")).unwrap();
        db.execute(corrupt, []).unwrap();
        drop(db);
        let mut runtime =
            RuntimeJournal::open(&root.0.join("runtime"), &"box".try_into().unwrap()).unwrap();
        assert!(runtime.disk(&record.request.id).is_err());
        assert!(
            runtime
                .acquire_disk(&record.request.id, &record.request_digest)
                .is_err()
        );
        assert!(
            runtime
                .retire_disk(&record.request.id, &record.request_digest)
                .is_err()
        );
        assert_eq!(
            fs::read(root.0.join("runtime/disk-bound.raw")).unwrap(),
            bytes
        );
    }
}

#[test]
fn abrupt_disk_copy_publication_and_deletion_reconcile_the_same_identity() {
    for stage in ["intent", "ready", "retired", "unlink"] {
        let root = Root::new();
        let bytes = vec![7; 65536];
        let source = root.source("base", &bytes);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "abrupt_disk_writer_child"])
            .env("SANDSURF_DISK_CRASH_ROOT", &root.0)
            .env("SANDSURF_DISK_CRASH_STAGE", stage)
            .output()
            .unwrap();
        assert_eq!(
            status.status.code(),
            Some(61),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        let mut runtime =
            RuntimeJournal::open(&root.0.join("runtime"), &"box".try_into().unwrap()).unwrap();
        let record = runtime.prepare_disk_copy(request("crash", &bytes)).unwrap();
        if stage == "intent" || stage == "ready" {
            runtime
                .materialize_disk(&record.request.id, &record.request_digest, &source)
                .unwrap();
            let held = runtime
                .acquire_disk(&record.request.id, &record.request_digest)
                .unwrap();
            let mut actual = vec![0; bytes.len()];
            held.duplicate_handle()
                .unwrap()
                .read_exact_at(&mut actual, 0)
                .unwrap();
            assert_eq!(actual, bytes);
        } else {
            assert!(
                runtime
                    .acquire_disk(&record.request.id, &record.request_digest)
                    .is_err()
            );
            assert_eq!(
                runtime
                    .cleanup_disk(&record.request.id, &record.request_digest)
                    .unwrap()
                    .phase,
                DiskPhase::Deleted
            );
        }
    }
}
