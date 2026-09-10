# Verifiable sandbox runtime

This repository provides prepared, policy-driven sandbox execution for Node.js. A preparation binds the selected implementation, explicit filesystem resources, resolved hard limits, executable bytes and identity, arguments, working directory, environment, and output requests before authorization.

Linux execution uses system bubblewrap; see [Linux requirements](docs/linux-backend.md).

The runtime fails closed. `probe()` reports observed mechanisms and request eligibility, while preparation opens and verifies the concrete resources. It never changes the requested filesystem layout or isolation boundary to find a fallback.

| Implementation | Boundary | Filesystem | Status |
| --- | --- | --- | --- |
| `linux-namespace-v1` | OS process | isolated | Stable when requested guarantees are supported |
| `windows-appcontainer-v1` | OS process | host | Experimental; object identity guarantees are not implemented |
| `darwin-seatbelt-v1` | OS process | host | Experimental; object identity guarantees are not implemented |
| `linux-firecracker-v1` | hardware virtualized | isolated imports | Experimental extension |

```ts
import { createSandbox } from "@ismail-elkorchi/sandbox";

const host = (path: string) => ({ space: "host" as const, path });
const isolated = (path: string) => ({ space: "isolated" as const, path });
const readExecute = {
  content: "read" as const,
  directoryEntries: "read" as const,
  metadata: "read" as const,
  execution: "allow" as const,
};

const sandbox = await createSandbox();
try {
  const options = {
    isolation: { kind: "process" as const },
    policy: {
      filesystem: {
        kind: "isolated" as const,
        resources: [
          {
            id: "shell",
            source: host("/bin"),
            target: isolated("/bin"),
            access: readExecute,
            purposes: ["executable" as const, "interpreter" as const],
          },
          // Dynamic executables also need explicit loader and library resources.
        ],
      },
      network: { mode: "none" as const },
      process: {
        visibility: "session" as const,
        control: "session" as const,
        termination: { scope: "descendant-tree" as const, graceMs: 100 },
      },
      ipc: { visibility: "session" as const },
    },
    requirements: {},
    process: {
      executable: isolated("/bin/sh"),
      args: ["-c", "printf hello"],
      cwd: isolated("/"),
    },
  };
  const support = await sandbox.probe(options);
  console.dir(support, { depth: null });
  if (support.implementations.some((value) => value.eligibility.state === "eligible")) {
    const result = await sandbox.run(options);
    console.log(result.stdout?.toString());
  }
} finally {
  await sandbox.dispose();
}
```

See [getting started](docs/getting-started.md), [policy](docs/policy.md), [implementation support](docs/backends.md), and the [threat model](docs/threat-model.md).

Licensed under Apache-2.0.
