#![cfg(target_os = "linux")]

//! Kernel-backed process-envelope experiments, not VM qualification. Each
//! experiment owns a separate unit: deliberate OOM cannot target the runner.
use sandsurf_native::resources::{ProcessEnvelope, systemd_properties, unit_name};
use sandsurf_protocol::{Counter, Resources};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn limits() -> Resources {
    let mut value = Resources::from_geometry(
        Counter::ONE,
        128.try_into().unwrap(),
        (1024 * 1024).try_into().unwrap(),
        Counter::ONE,
        Counter::ONE,
    )
    .unwrap();
    value.cpu_quota_micros = 25_000.try_into().unwrap();
    value.host_overhead_bytes = 4096.try_into().unwrap();
    value
}

#[test]
fn envelope_child() {
    let Some(root) = std::env::var_os("SANDSURF_ENVELOPE_FIXTURE") else {
        return;
    };
    let root = PathBuf::from(root);
    let envelope = ProcessEnvelope::current(&root, &limits()).unwrap();
    if std::env::var_os("SANDSURF_ENVELOPE_OOM").is_some() {
        let mut allocations = Vec::new();
        // Touch every page; virtual reservations alone do not test memory.max.
        for _ in 0..256 {
            allocations.push(vec![0xab_u8; 1024 * 1024]);
        }
        std::hint::black_box(&allocations);
        panic!("kernel memory cap did not contain the owned child");
    }
    let before = envelope.usage().unwrap().cpu_micros.get();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        std::hint::black_box(17_u64.wrapping_mul(43));
    }
    let cpu = envelope.usage().unwrap().cpu_micros.get() - before;
    assert!(cpu >= 250_000, "CPU workload did not execute: {cpu}");
    assert!(cpu < 1_300_000, "25% quota did not throttle CPU: {cpu}");
    println!("EXTERNAL-CPU-BOUND {cpu}");
    std::io::stdout().flush().unwrap();
}

#[test]
fn owned_unit_throttles_cpu_and_contains_actual_memory_exhaustion() {
    if std::env::var_os("SANDSURF_NATIVE_RESOURCE_TEST").is_none() {
        return;
    }
    let root = std::env::temp_dir().join(format!(
        "sandsurf-envelope-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    sandsurf_native::local::create_private_directory(&root).unwrap();
    for oom in [false, true] {
        let mut command = Command::new("systemd-run");
        command.args([
            "--user",
            "--wait",
            "--pipe",
            "--collect",
            "--service-type=exec",
            "--unit",
            &unit_name(&root).unwrap(),
        ]);
        for property in systemd_properties(&limits()).unwrap() {
            command.arg(format!("--property={property}"));
        }
        command.arg("--property=RuntimeMaxSec=15");
        command.arg(format!(
            "--setenv=SANDSURF_ENVELOPE_FIXTURE={}",
            root.display()
        ));
        if oom {
            command.arg("--setenv=SANDSURF_ENVELOPE_OOM=1");
        }
        let output = command
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "envelope_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        if oom {
            assert!(!output.status.success());
            assert!(
                diagnostics.contains("oom-kill"),
                "failure was not kernel OOM containment: {diagnostics}"
            );
        } else {
            assert!(output.status.success(), "{diagnostics}");
            assert!(String::from_utf8_lossy(&output.stdout).contains("EXTERNAL-CPU-BOUND"));
        }
    }
    std::fs::remove_dir(&root).unwrap();
}
