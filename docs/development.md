# Development and qualification

Use Node.js 24 or newer and the repository's pinned Rust-compatible dependency graph.

```sh
npm ci
npm run check
npm test
npm run verify:native
npm run test:package
npm run test:scripts
npm run audit:licenses
npm run audit:unsafe
```

`npm run test:package` installs the packed unscoped `sandsurf` package and verifies its public declarations and platform artifact selection. Source CI compiles the Linux, macOS and Windows adapters independently of hardware-dependent image builds. Package CI validates the committed current-format x64 image; ARM package validation and the five-platform release pipeline require a newly built ARM image on a native KVM host. Hosted image-build runners currently lack KVM, so that pipeline is blocked, not qualified or replaced by software emulation. A successful compile or prerequisite probe does not qualify a VM engine.

Archive creation streams npm's package selection directly to disk; it does not buffer complete machine images or the compressed tarball in Node memory. Distribution bundles contain gzip disk blobs, not multi-gigabyte mostly-empty ext4/VHDX files inside npm's tar stream. Native imports decode those blobs in bounded chunks into a private host-owned staging directory, verify the original manifest and every decoded artifact digest, then atomically publish the VM-native image. The immutable manifest identifies the computer independently of this transport. There is no raw-distribution fallback; raw disks are the internal materialized representation. Package lifecycle hooks are prohibited: build and verify the image/native artifacts explicitly before packing.

The deterministic parser smoke harness is `npm run fuzz:smoke`. The trust-boundary libFuzzer set is:

```sh
for target in sandsurf_protocol canonical_digest network_rules network_packet image_manifest image_archive guest_protocol firecracker_api; do
  cargo +nightly fuzz run "$target" -- -max_total_time=30 -max_len=1048576
done
```

Build a local guest image on native Linux with writable KVM, libguestfs (`guestfish`), native QEMU, and, for x64 VHDX conversion, qemu-img. Package resolution, lifecycle scripts and filesystem manipulation run inside the hardware-isolated appliance. There is no TCG, host-mount or host-chroot fallback. Its host kernel must be readable by the build account. Filesystem construction uses a fixed journaled, online-growable ext4 profile. The guest grows its own filesystem; the host never repairs or resizes a guest-controlled filesystem.

```sh
SANDSURF_LOCAL_IMAGE=1 \
SANDSURF_IMAGE_OUTPUT_DIRECTORY=/absolute/output \
npm run build:guest-image
```

The following isolated image tests require native KVM and libguestfs. They are
explicitly ignored in source-only tests and run in the image-build workflow:

```sh
cargo test --locked -p sandsurf-image isolated_materialization_preserves_linux_metadata -- --ignored --test-threads=1
cargo test --locked -p sandsurf-image managed_disk_clones_replace_os_identity_and_preserve_source -- --ignored --test-threads=1
cargo test --locked -p sandsurf-host converted_machine_seed_has_a_verified_internal_journal -- --ignored --test-threads=1
```

Release images require the private signing seed through `SANDSURF_IMAGE_SIGNING_KEY_FILE`; the seed must never enter the repository or logs. Firecracker downloads are digest-verified by `npm run fetch:firecracker` and never occur during package installation or workload execution.

On a qualified Linux x64 host, `SANDSURF_KVM_TEST=1 npm run test:package` runs the persistent-computer suite using the installed tarball's SDK, native binary and image. Build serially on memory-constrained hosts; do not compile while VM qualification is running.

Real VM qualification is separate. `npm run qualify:linux -- /absolute/new-report.json` first records native containment/NIC eligibility. A denied TAP setup exits 2 with a blocked report, without changing AppArmor, capabilities or host networking. Only an eligible host proceeds to the real installed-computer suite. The independent source-quality and installed-package jobs do not treat a blocked hardware run as a pass.

Linux image imports use one independently supervised worker pool per host directory (1 CPU, 1 GiB RAM, no swap, 64 host tasks, 300-second runtime). The API and artifact workers have a separate 1-CPU, 512-MiB, 256-task pool; supervision has a separate 1-CPU, 128-MiB, 64-task pool. These budgets are reserved before VM admission, and kernel controllers are verified before serving. The API admits immutable jobs and commits results; the image worker cannot mutate the catalog. Result bytes survive API restart. A busy or interrupted pool retains the admitted operation rather than silently launching additional workers. Other adapters explicitly report these pools as unsupported until their external envelopes exist. Aggregate physical-storage quota is not implied by process limits or capacity reservations.

Persistent machine/image storage rejects Linux tmpfs and ramfs rather than charging VM disks as anonymous host memory. Machine creation and native image imports additionally require dedicated bounded ext4 block volumes. Mount roots, device identities, aliasing, descendant mounts and block capacities are verified; ordinary directories, bind aliases and RAM filesystems are not physical caps. Machine snapshots and output remain on the owning machine volume, including after destruction. libguestfs scratch/cache stays beside the owned disk. Sandsurf does not mount, resize or recycle operator volumes.

For positive installed-image tests, set `SANDSURF_PACKAGE_TEST_DIRECTORY` to an operator-provisioned private host volume. Without it, installed-package tests verify explicit unsupported storage, binary transport and declarations without claiming image-import qualification. VM qualification requires `SANDSURF_QUALIFICATION_ROOT`, whose fixture layout and identities are included in the prerequisite report. Provision a separate shared host volume for each fixture and an independent 8GiB volume at each identity's `storage-path`. Qualification keeps retained evidence; cleanup/unmount/recycling is an explicit later operator action. Missing storage or native NIC prerequisites exits 2 before VM tests. Neither hosted CI success nor a blocked local run qualifies these mechanisms.

Platform qualification requirements:

- Linux requires writable KVM, the source-built guest image, containment checks, interrupted-operation recovery, installed-package validation, and the KVM environment suite.
- macOS requires a virtualization-enabled real Mac, an entitled candidate helper, guest boot/control tests, owner-death containment, and installed-package validation. Hosted CI where `VZVirtualMachine.isSupported` is false remains unqualified.
- Windows requires a Hyper-V/HCS-capable runner, registered Hyper-V socket service, Linux guest boot/control tests, HCS owner/ACL cleanup checks, interrupted recovery, and installed-package validation.

Qualification evidence is exact to the engine, architecture, boot bundle, helper/VMM, guest protocol, and tested host configuration. Unsupported mechanisms fail explicitly; there is no host-process or cloud fallback.
