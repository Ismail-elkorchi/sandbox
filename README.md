# Sandsurf

Sandsurf is the persistent hardware-isolated Linux environment underlying autonomous agents. A Machine owns a Linux machine, writable filesystem, processes, terminals, network authority, resource envelope, durable identity, and lifecycle. Executions happen inside that environment; they do not define its lifetime.

The public distribution is the unscoped npm package `sandsurf`. Its TypeScript API connects to an independently running native host service. The host owns authority changes, reservations, and lifecycle intent. A separate guardian process per Machine owns native observations, guest transport and retained runtime evidence; guest reports are not attestations.

Native engines are Firecracker/KVM on Linux, Virtualization.framework on macOS, and Hyper-V/HCS on Windows. Native support and hardware qualification are reported separately—Sandsurf never falls back to running guest programs as host processes. Linux machine admission requires operator-provisioned bounded host and machine volumes. Complete external resource enforcement is currently unsupported on macOS and Windows, so those adapters refuse unenforced machine creation. Real VM qualification remains separate from source and package validation; consult the current security scope before relying on containment or recovery guarantees.

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
