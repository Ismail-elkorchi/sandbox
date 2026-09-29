# Getting started

Install Node.js 24 or newer and the unscoped package:

```sh
npm install sandsurf
```

Use a private state directory and an application authorizer for host-authority changes. Ordinary commands and guest filesystem operations do not request new host authority.

```ts
import { Sandsurf } from "sandsurf";

const host = await Sandsurf.open({
  directory: "/private/application-state/sandsurf",
  authorizer: async (change) => approveInApplication(change),
});
const support = await host.inspect();
console.dir(support); // Unsupported mechanisms and unqualified ones are distinct.

const machine = await host.machines.create({
  image: "<verified-machine-image-sha256>",
  resources: {
    vcpus: 2,
    memoryMiB: 4096,
    diskBytes: 20 * 1024 ** 3,
    outputBytes: 1024 ** 3,
    managedExecutions: 512,
  },
});

await machine.artifacts.importFromHost({
  source: "/absolute/project",
  destination: "/workspace",
});
const execution = await machine.executions.start({
  argv: ["npm", "test"],
  cwd: "/workspace",
});
const completion = await execution.waitCapture();
for await (const chunk of execution.output.follow()) {
  consume(chunk.stream, chunk.bytes);
}
await host.close();
```

OCI conversion accepts a complete Linux OS filesystem with an executable
`/sbin/init` and an explicit boot-image recipe:

```ts
const image = await host.images.importOCI({
  source: { kind: "layout", path: "/absolute/oci-layout" },
  recipe: { bootImage: "<verified-boot-image-sha256>" },
});
```

The recipe selects verified native kernel artifacts. OCI `ENTRYPOINT` and
`CMD` do not become PID 1. The source filesystem must supply its own guest
management integration if guest APIs are needed. Conversion does not run
package scripts on the host. Journaled OCI conversion currently requires a
Linux builder; other hosts report that limitation explicitly.

Closing an SDK connection does not stop Linux or its services. Reconnect using the same host directory and durable identities:

```ts
const next = await Sandsurf.open({ directory, authorizer });
const reconnected = await next.machines.connect(machine.id);
const sameExecution = await reconnected.executions.get(execution.id);
```

The default guest account obtains root through ordinary `sudo`. Root can change the OS and disable management. Management failure is reported independently of native power state; `powerOff()` and `destroy()` do not require a responsive management service. Guest process results are observations, not host attestations.

Use `machine.fs` for guest paths. Artifact import, capture, comparison and host application operate on explicitly selected content. Host publication requires approval of immutable retained content and its destination. Snapshots, forks, rollback, networking, secrets and publication are independent capabilities, not a prescribed workflow.

Terminals are PTY executions with replayable `terminal` output. Detaching or cancelling a wait does not terminate an execution. Leader exit and output completion are separate; descendants may continue to hold streams open.

Receipt acknowledgement does not release output or express application acceptance. Release requires complete capture elsewhere, continuing retention of the actual bytes, or explicitly authorized loss. A receipt reference alone preserves no bytes. Machine destruction must not release retained output.

The breaking redesign remains incomplete. Native network attachments, unified storage recovery, full-state execution lineage and platform hardware qualification still require implementation or qualification; consult the reported capabilities and [security scope](../SECURITY.md).
