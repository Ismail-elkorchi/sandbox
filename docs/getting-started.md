# Getting started

Install Node.js 24 or newer and the unscoped package:

```sh
npm install sandsurf
```

Open an explicit private state directory and install an application authorizer. The authorizer is called for authority-changing operations; it is not called for every ordinary process or file request inside an already granted envelope.

```ts
import { Sandsurf } from "sandsurf";

const host = await Sandsurf.open({
  directory: "/private/application-state/sandsurf",
  authorizer: async (change) => approveInApplication(change),
});

const support = await host.inspect();
if (support.lifecycle.kind !== "qualified") {
  throw new Error(support.lifecycle.reasons.join("; "));
}

const image = await host.images.importOCI({
  reference: "registry.example/dev@sha256:<digest>",
  platform: support.guestPlatform,
});

const box = await host.sandboxes.create({
  image: image.id,
  resources: {
    vcpus: 2,
    memoryMiB: 4096,
    diskBytes: 20 * 1024 ** 3,
    outputBytes: 1024 ** 3,
    processes: 512,
  },
  capabilities: {
    spawn: true,
    "read-files": true,
    "write-files": true,
    "release-evidence": true,
  },
});

await box.workspace.importFromHost({ source: "/absolute/project" });
const process = await box.processes.spawn({
  argv: ["npm", "test"],
  cwd: "/workspace",
});
const completion = await process.wait();

for await (const chunk of process.output.follow()) {
  consume(chunk.stream, chunk.bytes);
}
```

A Sandbox is persistent. `host.close()` detaches the client; it does not stop the machine or its sandbox-lifetime processes. Reopen the same state directory and reconnect by the durable Sandbox and process identities:

```ts
const next = await Sandsurf.open({ directory, authorizer });
const resumed = await next.sandboxes.connect(box.id);
const sameProcess = await resumed.processes.get(process.id);
```

Use `box.fs` for guest paths and `box.workspace` for explicit host import, diff, export, and conflict-checked apply. Host paths never become ordinary guest file paths. Network policy, inbound ports, secrets, resources, checkpoints, forks, rollback, and image publication are independent capabilities rather than a required workflow.

Terminal processes use `stdio: "terminal"`; their replay stream is `terminal`, not guessed stdout/stderr. Cancelling a client wait does not terminate a process. Call `terminate()` or `signal()` explicitly.

Terminal receipts, acknowledgement, output capture, and evidence release are distinct. Before `complete-capture` release, persist every byte through the receipt's final cursor together with the capture manifest. A receipt reference alone does not preserve output. Use a retention pin to keep bytes in Sandsurf, or obtain explicit authorization for loss.
