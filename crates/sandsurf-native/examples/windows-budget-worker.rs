//! Native kernel fixture, never distributed as a product executable.
#[cfg(windows)]
fn main() {
    use std::time::{Duration, Instant};
    let mut args = std::env::args_os().skip(1);
    match args
        .next()
        .and_then(|value| value.into_string().ok())
        .as_deref()
    {
        Some("exit259") => std::process::exit(259),
        Some("spin") => {
            let start = Instant::now();
            let mut work = 1u64;
            while start.elapsed() < Duration::from_secs(5) {
                work = std::hint::black_box(work.wrapping_mul(6364136223846793005).wrapping_add(1));
            }
            std::hint::black_box(work);
        }
        Some("memory") => {
            let mut bytes = vec![0u8; 128 * 1024 * 1024];
            for offset in (0..bytes.len()).step_by(4096) {
                bytes[offset] = 42;
            }
            std::hint::black_box(bytes);
            std::process::exit(99);
        }
        Some("no-child") => {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("exit259")
                .spawn();
            match result {
                Err(_) => {}
                Ok(mut child) => {
                    let _ = child.wait();
                    std::process::exit(99);
                }
            }
        }
        Some("hold") => std::thread::sleep(Duration::from_secs(30)),
        Some("disk-access") => {
            use std::io::{Read, Write};
            use std::os::windows::io::FromRawHandle;
            #[repr(align(4096))]
            struct Sector([u8; 4096]);
            assert_eq!(args.next().unwrap(), "--sandsurf-disk-handles");
            let mut disks: [std::fs::File; 2] = std::array::from_fn(|_| {
                let handle: usize = args.next().unwrap().to_str().unwrap().parse().unwrap();
                // SAFETY: this fixture consumes each explicit inherited disk
                // handle exactly once; the parent's launch provided originals.
                unsafe { std::fs::File::from_raw_handle(handle as _) }
            });
            assert!(args.next().is_none());
            let bytes = Sector([42; 4096]);
            disks[0].write_all(&bytes.0).unwrap();
            disks[0].sync_all().unwrap();
            assert_eq!(
                disks[1].write(&bytes.0).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            let mut original = Sector([0; 4096]);
            disks[1].read_exact(&mut original.0).unwrap();
            assert_eq!(original.0, [0; 4096]);
        }
        Some("owner") => {
            use sandsurf_native::{owned_windows::OwnedWorker, process_budget::ProcessBudget};
            use std::io::Write;
            let root = std::path::PathBuf::from(args.next().unwrap());
            let custody = sandsurf_native::storage::disk_lease(&root.join("disk.lock")).unwrap();
            let snapshot =
                sandsurf_native::storage::read_lease(&root.join("snapshot.lock")).unwrap();
            let disks = std::array::from_fn(|slot| {
                let path = root.join(format!("io-{slot}"));
                let file = sandsurf_native::local::create_private_file(&path).unwrap();
                file.set_len(4096).unwrap();
                drop(file);
                sandsurf_native::owned_windows::disk_input(&path, slot == 1).unwrap()
            });
            let worker = OwnedWorker::launch_vm(
                &std::env::current_exe().unwrap(),
                &["hold".into()],
                ProcessBudget {
                    cpu_quota_micros: 25000,
                    memory_bytes: 64 * 1024 * 1024,
                    processes: 1,
                },
                vec![std::sync::Arc::new(custody), std::sync::Arc::new(snapshot)],
                disks,
            )
            .unwrap();
            let mut ready =
                sandsurf_native::local::create_private_file(&root.join("ready")).unwrap();
            write!(ready, "{}", worker.process_id()).unwrap();
            ready.sync_all().unwrap();
            std::thread::sleep(Duration::from_secs(30));
            drop(worker);
        }
        _ => panic!("invalid native worker fixture"),
    }
}
#[cfg(not(windows))]
fn main() {
    panic!("Windows kernel fixture requires Windows");
}
