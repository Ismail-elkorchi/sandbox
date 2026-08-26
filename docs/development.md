# Development and release verification

## Toolchains

- Node.js 24 or newer.
- Rust stable 1.88 or newer with `rustfmt` and `clippy`.
- Nightly Rust and `cargo-fuzz` for libFuzzer targets.
- `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` targets for Linux release runtimes.
- Platform-native SDK/toolchains for Windows and macOS backends.
- Writable `/dev/kvm` for real Firecracker conformance.

Install JavaScript development dependencies with `npm ci` in a clean checkout.

## Fast checks

```sh
npm run build:ts
npm run check
npm run test:rust
npm run test:ts
```

`npm run check` runs strict TypeScript builds, `cargo fmt --check`, and workspace Clippy with warnings denied.

## Full local verification

```sh
npm test
npm run verify:native
npm run test:package
npm run audit:licenses
npm run audit:unsafe
cargo audit --deny warnings
cargo audit --file fuzz/Cargo.lock --deny warnings
```

Native tests probe required host functionality and report an explicit skip when the current machine cannot enforce a backend. A Linux machine without usable namespaces or Landlock is not treated as a backend test pass. Windows and macOS conformance must run on their native hosts.

## Fuzzing

The deterministic smoke harness is:

```sh
npm run fuzz:smoke
```

Run every trust-boundary libFuzzer target with nightly Rust:

```sh
for target in protocol control_messages canonical_digest policy paths host_paths environment_block windows_arguments network_rules dns socks5 http_connect image_manifest guest_protocol artifact_manifest changesets; do
  cargo +nightly fuzz run "$target" -- -max_total_time=30 -max_len=1048576
done
```

The targets cover framing, control messages, canonical encoding, policy and paths, environment blocks, platform argument encoding, managed-network parsers, images, guest messages, artifacts, and change sets.

## Native artifacts

```sh
npm run build:native
npm run verify:native
```

The build script creates the runtime for the current release target and updates its SHA-256 manifest. Release CI builds each native artifact on its target architecture and executes it there; cross-compilation alone does not qualify an artifact.

Linux release builds are static musl executables for x64 and ARM64. Windows and macOS builds use their system platform APIs and libraries.

## Firecracker artifacts

`npm run fetch:firecracker` verifies the pinned upstream Firecracker artifact. It is a build-time command and is never run during package installation or target execution.

The minimal guest build requires `mkfs.ext4`, `debugfs`, `curl`, `readelf`, a static BusyBox executable, a CA bundle, and an owner-only 32-byte Ed25519 seed whose public key matches the runtime:

```sh
SANDBOX_IMAGE_SIGNING_KEY_FILE=/absolute/private/release-seed npm run build:guest-image
npm run build:vm-native
npm run verify:native
```

The private signing seed must never be committed. The build is reproducible and replaces read-only artifacts atomically.

To run the real KVM suite, build its static guest target and execute the test file:

```sh
cargo build --release -p sandbox-conformance-target --target x86_64-unknown-linux-musl
node --test packages/sandbox/test/hardware-vm-conformance.test.mjs
```

## Supply chain and packages

```sh
npm run supply-chain
npm run test:package
npm run package
```

Supply-chain generation produces a CycloneDX SBOM and third-party notices for each npm package. Package tests install generated tarballs into a clean consumer, import both scoped packages, reject development output, and require package entry points and licenses.

Release tarballs are written to `release/`, which is intentionally ignored by Git. Published packages contain only declared JavaScript output, native artifacts, guest artifacts where applicable, their license, SBOM, and notices.

## CI layout

- `quality.yml` runs Linux tests, cross-target checks, audits, native macOS and Windows checks, and all fuzz targets.
- `release.yml` builds and executes native artifacts on Linux x64/ARM64, macOS x64/ARM64, and Windows x64 before assembling packages.
- `kvm-conformance.yml` runs Firecracker tests on a dedicated self-hosted KVM runner.

Do not mark a native backend available from compile success. Availability and release status require its functional probe and native conformance suite.
