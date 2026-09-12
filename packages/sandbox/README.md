# `@ismail-elkorchi/sandbox`

Fail-closed sandbox execution with prepared authorization, explicit resource manifests, scoped hard limits, structured termination, cleanup reports, and recovery support.

Filesystem and execution paths are tagged as host or isolated coordinates. The library does not add a system runtime: callers authorize every executable, interpreter, loader, library, cache, and data resource needed by the workload.

```ts
import { createSandbox } from "@ismail-elkorchi/sandbox";

const sandbox = await createSandbox();
const support = await sandbox.probe({
  isolation: { kind: "process" },
  policy,
  requirements: {},
  resources,
});

if (support.implementations.some((value) => value.eligibility.state === "eligible")) {
  const prepared = await sandbox.prepareRun({
    isolation: { kind: "process" },
    policy,
    requirements: {},
    resources,
    process: {
      executable: { space: "isolated", path: "/tools/program" },
      cwd: { space: "isolated", path: "/workspace" },
    },
  });
  const process = await prepared.start({
    policyDigest: prepared.policyDigest,
    executionDigest: prepared.executionDigest,
  });
  console.log(await process.wait());
}

await sandbox.dispose();
```

See the repository [policy guide](../../docs/policy.md) and [getting started guide](../../docs/getting-started.md).

Linux isolated process execution requires system bubblewrap at `/usr/bin/bwrap`, Landlock ABI 3 or later, and seccomp. A host-layout policy can use Landlock and seccomp when user namespaces or bubblewrap are unavailable. `probe()` reports host support for the supplied policy. Explicit memory and process-count limits additionally require writable cgroup delegation.
