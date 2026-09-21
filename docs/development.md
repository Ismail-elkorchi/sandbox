# Development and qualification

Use Node.js 24 or newer and the repository's pinned Rust-compatible dependency graph.

```sh
npm ci
npm run check
npm test
npm run verify:native
npm run test:package
npm run audit:licenses
npm run audit:unsafe
```

`npm run test:package` installs the packed unscoped `sandsurf` package and verifies its public declarations and platform artifact selection. Release CI builds native artifacts on Linux x64/arm64, macOS x64/arm64, and Windows x64. A successful compile or prerequisite probe does not qualify a VM engine.

The deterministic parser smoke harness is `npm run fuzz:smoke`. The trust-boundary libFuzzer set is:

```sh
for target in sandsurf_protocol canonical_digest policy paths network_rules dns socks5 http_connect image_manifest guest_protocol artifact_manifest changesets; do
  cargo +nightly fuzz run "$target" -- -max_total_time=30 -max_len=1048576
done
```

Build a local guest image only from source-built artifacts:

```sh
SANDSURF_LOCAL_IMAGE=1 \
SANDSURF_IMAGE_OUTPUT_DIRECTORY=/absolute/output \
npm run build:guest-image
```

Release images require the private signing seed through `SANDSURF_IMAGE_SIGNING_KEY_FILE`; the seed must never enter the repository or logs. Firecracker downloads are digest-verified by `npm run fetch:firecracker` and never occur during package installation or workload execution.

Real VM qualification is separate:

- Linux requires writable KVM, the source-built guest image, containment checks, interrupted-operation recovery, installed-package validation, and the KVM environment suite.
- macOS requires a virtualization-enabled real Mac, an entitled candidate helper, guest boot/control tests, owner-death containment, and installed-package validation. Hosted CI where `VZVirtualMachine.isSupported` is false remains unqualified.
- Windows requires a Hyper-V/HCS-capable runner, registered Hyper-V socket service, Linux guest boot/control tests, HCS owner/ACL cleanup checks, interrupted recovery, and installed-package validation.

Qualification evidence is exact to the engine, architecture, boot bundle, helper/VMM, guest protocol, and tested host configuration. Unsupported mechanisms fail explicitly; there is no host-process or cloud fallback.
