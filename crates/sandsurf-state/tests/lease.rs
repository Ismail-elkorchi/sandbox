#![cfg(unix)]

use sandsurf_protocol::*;
use sandsurf_state::*;
use std::fs;
use std::os::unix::fs::DirBuilderExt;

#[test]
fn intentional_writer_close_releases_a_fork_inherited_lease() {
    let root = std::env::temp_dir().join(format!(
        "sandsurf-fork-lease-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let limits = CatalogLimits {
        identities: Counter::ONE,
        operations: Counter::ONE,
        grants: Counter::ONE,
        usage_records: Counter::ONE,
        image_bytes: Counter::ONE,
        resources: Resources {
            vcpus: Counter::ONE,
            memory_mib: Counter::ONE,
            disk_bytes: Counter::ONE,
            output_bytes: Counter::ONE,
            processes: Counter::ONE,
        },
    };
    let host =
        HostCatalog::create(&root.join("host"), "fork-host".try_into().unwrap(), limits).unwrap();
    let mut pipe = [-1; 2];
    // SAFETY: pipe has room for the two new owned descriptors produced on success.
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    // SAFETY: the child calls only async-signal-safe libc functions and _exit;
    // it never uses the inherited Rust allocator or SQLite connection.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let mut descriptor = libc::pollfd {
            fd: pipe[0],
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: owned descriptors and a valid pollfd; no Rust cleanup after fork.
        unsafe {
            libc::close(pipe[1]);
            libc::poll(&mut descriptor, 1, 5_000);
            libc::_exit(0);
        }
    }
    drop(host);
    let reopened = HostCatalog::open(&root.join("host"));
    let wakeup = [1u8];
    let mut status = 0;
    // SAFETY: release the child's owned pipe wait and reap precisely the child
    // created above before asserting, including when journal reopen failed.
    unsafe {
        libc::write(pipe[1], wakeup.as_ptr().cast(), wakeup.len());
        libc::close(pipe[0]);
        libc::close(pipe[1]);
        libc::waitpid(pid, &mut status, 0);
    }
    assert!(
        reopened.is_ok(),
        "orderly close must not leave an inherited lease busy"
    );
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}
