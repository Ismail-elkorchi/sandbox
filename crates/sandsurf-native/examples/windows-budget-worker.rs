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
        Some("owner") => {
            use sandsurf_native::{owned_windows::OwnedWorker, process_budget::ProcessBudget};
            use std::io::Write;
            let root = std::path::PathBuf::from(args.next().unwrap());
            let custody = sandsurf_native::storage::disk_lease(&root.join("disk.lock")).unwrap();
            let snapshot =
                sandsurf_native::storage::read_lease(&root.join("snapshot.lock")).unwrap();
            let worker = OwnedWorker::launch_vm(
                &std::env::current_exe().unwrap(),
                &["hold".into()],
                ProcessBudget {
                    cpu_quota_micros: 25000,
                    memory_bytes: 64 * 1024 * 1024,
                    processes: 1,
                },
                vec![std::sync::Arc::new(custody), std::sync::Arc::new(snapshot)],
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
