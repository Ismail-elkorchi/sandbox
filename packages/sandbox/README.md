# `sandsurf`

Persistent hardware-isolated Linux environments for autonomous agents.

```ts
import { Sandsurf } from "sandsurf";

const host = await Sandsurf.open({
  directory: "/private/application-state/sandsurf",
  authorizer: async (change) => approve(change),
});

const support = await host.inspect();
const box = await host.sandboxes.create({
  image: "<verified-image-sha256>",
  resources: { vcpus: 2, memoryMiB: 4096, diskBytes: 20 * 1024 ** 3 },
  capabilities: { spawn: true, "read-files": true, "write-files": true },
});

const process = await box.processes.spawn({
  argv: ["npm", "test"],
  cwd: "/workspace",
  lifetime: "job",
});
const completion = await process.wait();

await host.close(); // The Sandbox and its services remain owned by the native host.
```

Sandsurf uses one unscoped npm package and a native host service. Linux uses Firecracker/KVM, macOS uses Virtualization.framework, and Windows uses Hyper-V/HCS. `inspect()` reports qualification honestly; no host-process or cloud fallback is selected when hardware virtualization is unavailable.

The host is the sole grant and lifecycle-intent authority. Per-Sandbox guardians own observed machine state, guest control, output retention, and runtime evidence. SDK handles retain identities and expected revisions, not a second grant database.
