# Sandsurf

Sandsurf is the persistent hardware-isolated Linux environment underlying autonomous agents. A Sandbox owns a Linux machine, writable filesystem, processes, terminals, network authority, resource envelope, durable identity, and lifecycle. Executions happen inside that environment; they do not define its lifetime.

The public distribution is the unscoped npm package `sandsurf`. Its TypeScript API connects to an independently running native host service. The host owns grants, reservations, and lifecycle intent. A separately supervised guardian per Sandbox owns observed machine state, guest control, runtime evidence, and retained output.

Native engines are Firecracker/KVM on Linux, Virtualization.framework on macOS, and Hyper-V/HCS on Windows. Unsupported or unqualified configurations fail explicitly—Sandsurf never falls back to running the workload as a host process.

```ts
import { Sandsurf } from "sandsurf";

const host = await Sandsurf.open({
  directory: "/private/application-state/sandsurf",
  authorizer: async (change) => approve(change),
});

const support = await host.inspect();
console.dir(support);
```

See [`packages/sandbox`](packages/sandbox) for the package and [`docs`](docs) for architecture, security, and qualification details.

Licensed under Apache-2.0.
