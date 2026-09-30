# `sandsurf`

Persistent hardware-isolated Linux environments for autonomous agents.

```ts
import { Sandsurf } from "sandsurf";

const host = await Sandsurf.open({
  directory: "/private/application-state/sandsurf",
  authorizer: async (change) => approve(change),
});

const support = await host.inspect();
const box = await host.machines.create({
  image: "<verified-image-sha256>",
  resources: { vcpus: 2, memoryMiB: 4096, diskBytes: 20 * 1024 ** 3 },
});

const execution = await box.executions.start({
  argv: ["npm", "test"],
  cwd: "/workspace",
});
const completion = await execution.waitCapture();

await host.close(); // The Machine and its services remain owned by the native host.
```

Sandsurf uses one unscoped npm package and a native host service. Linux uses Firecracker/KVM, macOS uses Virtualization.framework, and Windows uses Hyper-V/HCS. `inspect()` reports qualification honestly; no host-process or cloud fallback is selected when hardware virtualization is unavailable.

Installed operation uses two independent native services: the host API owns authority; the guardian supervisor launches the fixed per-machine owners. `sandsurf setup --directory /absolute/state --json` renders all required service files. Restarting the API service does not stop the supervisor's service group. SDK auto-start launches these roles separately, but detached processes do not escape an application's service-manager group; use the installed services for unattended lifetime. Account logout and host reboot do not promise RAM/process survival.

The guest administrator can use normal Linux privileges (including sudo), change the system and disable its management service. The host owns authority changes and lifecycle intent; guardians observe native state independently of management availability. SDK handles retain identities and expected revisions, not another authority database. Captured output is not released by acknowledging a receipt or disconnecting.

The breaking redesign is still in progress. Native network enforcement, storage recovery and full-state execution lineage are not yet qualified. Build and API tests are not substitutes for the reported hardware qualification.
