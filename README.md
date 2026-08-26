# Sandbox

`@ismail-elkorchi/sandbox` runs untrusted commands behind an explicit, fail-closed policy. Its TypeScript API separates preparation and approval from execution, while package-owned Rust runtimes enforce filesystem, process, resource, and network restrictions.

The project never falls back to an ordinary process when isolation is unavailable. Every prepared run includes authoritative policy and execution digests plus a guarantee-by-guarantee enforcement report.

## Packages

```sh
npm install @ismail-elkorchi/sandbox
```

Install the separate Firecracker extension only when hardware-VM isolation is needed:

```sh
npm install @ismail-elkorchi/sandbox-hardware-vm
```

Both packages require Node.js 24 or newer and have no runtime npm dependencies. Native executables are bundled and hash-verified; installation does not compile or download code.

## Backends

| Backend | Host | Status | Network modes |
| --- | --- | --- | --- |
| `linux-namespace-v1` | Linux x64 and ARM64 | Stable | `none`, `managed`, acknowledged `unrestricted` |
| `windows-appcontainer-v1` | Windows x64 | Experimental | `none` |
| `darwin-seatbelt-v1` | macOS x64 and ARM64 | Experimental | `none`, acknowledged `unrestricted` |
| `linux-firecracker-v1` | Linux x64 with KVM | Experimental extension | `none`, `managed` |

Experimental backends require explicit opt-in and report their limitations. A functional probe determines whether the selected backend is actually usable on the current host.

## Linux quick start

```ts
import { resolve } from "node:path";
import {
  createSandbox,
  LINUX_PROCESS_BASELINE_REQUIREMENTS,
} from "@ismail-elkorchi/sandbox";

const workspace = resolve("./workspace");
const sandbox = await createSandbox();

try {
  const prepared = await sandbox.prepareRun({
    isolation: { kind: "process" },
    policy: {
      filesystem: {
        runtime: { kind: "system" },
        grants: [{
          hostPath: workspace,
          targetPath: "/workspace",
          access: "read-write",
        }],
      },
      network: { mode: "none" },
      process: { hostProcesses: "deny", hostIpc: "deny" },
    },
    requirements: LINUX_PROCESS_BASELINE_REQUIREMENTS,
    resources: {
      wallTimeMs: 30_000,
      memoryBytes: 512 * 1024 * 1024,
      maxProcesses: 32,
      maxOutputBytes: 8 * 1024 * 1024,
    },
    process: {
      executable: "/bin/sh",
      args: ["-c", "cat input.txt > output.txt"],
      cwd: "/workspace",
      environment: { base: "minimal" },
      stdout: "capture",
      stderr: "capture",
    },
  });

  // Present these exact values to the authorization layer.
  console.dir(prepared.summary, { depth: null });
  console.dir(prepared.enforcement, { depth: null });

  const process = await prepared.start({
    policyDigest: prepared.policyDigest,
    executionDigest: prepared.executionDigest,
  });
  const result = await process.wait();

  if (!result.cleanup.completed) {
    throw new Error(`sandbox cleanup failed: ${JSON.stringify(result.cleanup.failures)}`);
  }
  console.log(result.termination);
} finally {
  await sandbox.dispose();
}
```

The executable and arguments are always transported separately. The example invokes a shell deliberately; the sandbox never inserts one implicitly. `sandbox.run()` is a convenience for callers that do not need an external approval step.

## How authorization works

1. `prepareRun()` normalizes the request and secures the referenced filesystem and executable authority.
2. The Rust runtime returns a redacted summary, enforcement report, policy digest, and execution digest.
3. The caller approves those returned values.
4. `start()` consumes the prepared object once and rejects expired or mismatched digests.
5. The result reports structured termination, resource usage, violations, and verified cleanup outcomes.

Environment values marked `sensitive` affect execution identity but are omitted from summaries and ordinary errors.

## Documentation

- [Documentation index](docs/README.md)
- [Getting started and lifecycle](docs/getting-started.md)
- [Policies and requirements](docs/policy.md)
- [Backend support and caveats](docs/backends.md)
- [Managed networking](docs/managed-networking.md)
- [Firecracker hardware VMs](docs/hardware-vm.md)
- [Security model](docs/threat-model.md)
- [Development and release checks](docs/development.md)
- [Protocol reference](docs/protocol.md)

## Security status

The Linux process backend is suitable for serious local isolation when its functional probe and requested guarantees succeed. Native-process isolation still shares the host kernel. The Firecracker, Windows, and macOS backends are experimental.

This project does **not** claim suitability for hostile multi-tenant workloads. That claim remains blocked until an independent security review is completed and its scope and tested versions are published. Report suspected vulnerabilities through the process in [`SECURITY.md`](SECURITY.md).

## Development

The main local verification command is:

```sh
npm test
```

See [development.md](docs/development.md) for prerequisites, fuzzing, native builds, KVM tests, package verification, and release artifacts.

## License

Apache-2.0. See [`LICENSE`](LICENSE). Third-party notices and CycloneDX SBOMs are included in each package.
