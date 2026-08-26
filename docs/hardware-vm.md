# Firecracker hardware VMs

The experimental `linux-firecracker-v1` backend provides a hardware-virtualized boundary on Linux x64 hosts with KVM. It is distributed separately so process-only consumers do not install a VMM or guest image.

## Install and register

```sh
npm install @ismail-elkorchi/sandbox @ismail-elkorchi/sandbox-hardware-vm
```

```ts
import { createSandbox } from "@ismail-elkorchi/sandbox";
import {
  hardwareVmExtension,
  minimalHardwareVmImage,
} from "@ismail-elkorchi/sandbox-hardware-vm";

const sandbox = await createSandbox({
  allowExperimentalBackends: true,
  extensions: [hardwareVmExtension()],
});

const support = await sandbox.probe({ isolation: "hardware-vm" });
```

Registration verifies the package-owned extension descriptor and native runtime before either is executed. The backend probe additionally requires readable and writable `/dev/kvm`, verified Firecracker and boot artifacts, a compatible host architecture, and successful abandoned-state recovery.

## Run with explicit imports

```ts
const result = await sandbox.run({
  isolation: {
    kind: "hardware-vm",
    image: minimalHardwareVmImage(),
    filesystemTransport: "import",
  },
  policy: {
    filesystem: {
      runtime: { kind: "empty" },
      grants: [{
        hostPath: "/absolute/workspace",
        targetPath: "/workspace",
        access: "read-write",
        execution: "allow",
      }],
    },
    network: { mode: "none" },
    process: { hostProcesses: "deny", hostIpc: "deny" },
  },
  requirements: {
    boundary: "hardware-virtualized",
    allowExperimentalBackend: true,
    required: [
      "runtime.setup-before-exec",
      "runtime.no-ambient-environment",
      "runtime.no-ambient-handles",
      "vm.boot-artifacts-verified",
      "vm.guest-control-authenticated",
      "vm.control-plane-hidden-from-target",
      "vm.host-filesystem-absent-outside-imports",
      "process.complete-tree-termination",
      "resource.wall-time-hard",
      "resource.output-hard",
    ],
  },
  resources: {
    wallTimeMs: 30_000,
    memoryBytes: 512 * 1024 * 1024,
    maxProcesses: 64,
  },
  process: {
    executable: "/workspace/tool",
    args: ["build"],
    cwd: "/workspace",
    stdout: "capture",
    stderr: "capture",
    artifacts: {
      paths: ["/workspace/output"],
      maxBytes: 16 * 1024 * 1024,
    },
    changeSet: { maxBytes: 32 * 1024 * 1024 },
  },
});
```

`import` copies bounded grant content into an ephemeral workspace. The guest never receives a host directory mount. `ephemeral` starts without imports and therefore rejects host grants.

Imported executables must be compatible with the minimal Linux guest. The bundled image is deliberately small; it is not a general-purpose distribution.

## Artifact export

Artifacts are exported only from explicitly requested guest paths and are returned as a digest-bound manifest plus bounded content. Export does not write to host paths. The caller decides how and where to materialize the returned files.

Traversal, unsupported object types, size overflows, duplicate paths, symlink escapes, and digest mismatches fail the export.

## Workspace change sets

A requested change set compares the guest workspace with the content-bound import base. It does not automatically synchronize changes back to the host.

```ts
import {
  applyHardwareVmChangeSet,
  recoverHardwareVmChangeSets,
} from "@ismail-elkorchi/sandbox-hardware-vm";

const change = result.changeSets?.[0];
if (change !== undefined) {
  await applyHardwareVmChangeSet({
    rootPath: "/absolute/workspace",
    recoveryDirectory: "/absolute/private-recovery-directory",
    changeSet: change.changeSet,
  });
}

await recoverHardwareVmChangeSets("/absolute/private-recovery-directory");
```

Apply validates the change-set digest, base manifest, operation ordering, current host content, and descriptor-relative paths. Conflicts fail before mutation. The apply journal records original objects and supports explicit recovery after interruption.

Keep the recovery directory private to the trusted host process. Do not place it inside the untrusted workspace.

## Image trust

`minimalHardwareVmImage()` selects the project-signed bundled manifest. The runtime verifies the manifest signature and exact manifest, kernel, rootfs, guest-agent, Firecracker, and workspace-template digests. Missing artifacts fail locally; the runtime never downloads an image.

Advanced callers may provide an `explicit-local` image only through an extension descriptor that enables it. Explicit-local trust means the caller endorses the local manifest; artifact format, architecture, bounds, and all declared hashes are still verified and bound into preparation.

## Control and network separation

The host and privileged guest agent authenticate each message channel with a fresh random nonce. The target has no nonce, control descriptor, or Virtio socket device. The guest agent performs setup and supervision; the target executes after isolation in a separate process context.

`network: "none"` creates no virtual NIC. Managed networking also creates no NIC; supported TCP and DNS requests cross the authenticated guest channel to the host broker.

## Lifecycle and cleanup

The host runtime confines Firecracker inside the Linux process backend with access only to `/dev/kvm`, verified boot artifacts, and private state. Cancellation kills the VMM tree and guest. Owner leases, parent-death signals, and random ownership tokens let the next probe recover state after a runtime `SIGKILL` without killing unrelated processes.

Cleanup reports VMM death, broker shutdown, state removal, and every failed postcondition. The backend remains experimental even when all requested guarantees are satisfied.
