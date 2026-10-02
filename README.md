# Sandsurf

Sandsurf is the persistent hardware-isolated Linux environment underlying autonomous agents. A Machine owns a Linux machine, writable filesystem, processes, terminals, network authority, resource envelope, durable identity, and lifecycle. Executions happen inside that environment; they do not define its lifetime.

The public distribution is the unscoped npm package `sandsurf`. Its TypeScript API connects to an independently running native host service. The host owns authority changes, reservations, and lifecycle intent. A separate guardian process per Machine owns native observations, guest transport and retained runtime evidence; guest reports are not attestations.

Native engines are Firecracker/KVM on Linux and Sandsurf-owned QEMU using HVF on macOS or WHPX on Windows, with no software-emulation backend. Machine admission requires operator-provisioned bounded host and machine volumes and the adapter's complete enforced envelope. Inspect the host for supported operations and missing prerequisites: cross-platform image-worker integration is not yet complete. Real VM qualification remains separate from source and package validation; consult the current security scope before relying on containment or recovery guarantees.

```ts
import { Sandsurf } from "sandsurf";

const host = await Sandsurf.open({
  directory: "/private/application-state/sandsurf",
  authorizer: async (change) => approve(change),
});

const support = await host.inspect();
console.dir(support);
```

See [`packages/sandsurf`](packages/sandsurf) for the package and [`docs`](docs) for architecture, security, and qualification details.

Licensed under Apache-2.0.
