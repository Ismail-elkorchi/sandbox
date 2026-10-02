//! CI-only installed worker fixture. Never included in the npm distribution.
#[cfg(target_os = "macos")]
fn main() {
    use sandsurf_native::resource_broker::{WorkerKind, macos::enter_worker};
    use std::io::Write;
    use std::time::{Duration, Instant};
    let mut args = std::env::args().skip(1);
    assert_eq!(args.next().as_deref(), Some("--broker-worker"));
    let role = WorkerKind::parse(&args.next().unwrap()).unwrap();
    assert!(matches!(
        role,
        WorkerKind::Api | WorkerKind::VirtualMachine | WorkerKind::Images
    ));
    let budget = enter_worker().unwrap();
    match args.next().as_deref() {
        Some("cpu") => {
            let usage = sandsurf_native::resource_broker::macos::current_worker_usage().unwrap();
            assert!(usage.memory_current > 0);
            assert!(usage.owner_start_ticks > 0 && usage.worker_start_ticks > 0);
            let initial = cpu();
            let start = Instant::now();
            let mut work = 1u64;
            while start.elapsed() < Duration::from_secs(5) {
                work = std::hint::black_box(work.wrapping_mul(6364136223846793005).wrapping_add(1));
            }
            println!(
                "{} {} {}",
                cpu() - initial,
                start.elapsed().as_micros(),
                budget.cpu_quota_micros
            );
            std::hint::black_box(work);
        }
        Some("memory") => {
            let mut bytes = vec![0u8; 128 * 1024 * 1024];
            for offset in (0..bytes.len()).step_by(4096) {
                bytes[offset] = 42;
            }
            std::hint::black_box(&bytes);
            // A process which survives touched pages above 64MiB falsifies the
            // hard physical limit; this is not a memory-usage sampling test.
            println!("escaped fatal physical-memory limit");
            std::process::exit(99);
        }
        Some("durable") => {
            let path = args.next().unwrap();
            std::thread::sleep(Duration::from_millis(500));
            let mut file =
                sandsurf_native::local::create_private_file(std::path::Path::new(&path)).unwrap();
            file.write_all(b"retained after observer disconnection")
                .unwrap();
            file.sync_all().unwrap();
        }
        Some("owner-loss") => {
            std::thread::sleep(Duration::from_secs(30));
        }
        Some("image-custody") => {
            assert_eq!(role, WorkerKind::Images);
            let root = std::path::PathBuf::from(args.next().unwrap());
            let held = sandsurf_native::resource_broker::macos::receive_image_lease(
                &root.join("image-pool.lock"),
            )
            .unwrap();
            let mut ready =
                sandsurf_native::local::create_private_file(&root.join("image-ready")).unwrap();
            ready.write_all(b"original transferred custody").unwrap();
            ready.sync_all().unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !root.join("image-release").exists() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(20));
            }
            drop(held);
        }
        _ => panic!("invalid native budget fixture"),
    }

    fn cpu() -> u64 {
        // SAFETY: rusage is a public integer/timeval ABI output layout.
        let mut value: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: a complete writable rusage is supplied for this process only.
        assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut value) }, 0);
        let micros = |time: libc::timeval| -> u64 {
            u64::try_from(time.tv_sec).unwrap() * 1_000_000 + u64::try_from(time.tv_usec).unwrap()
        };
        micros(value.ru_utime) + micros(value.ru_stime)
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    panic!("Darwin kernel fixture requires macOS");
}
