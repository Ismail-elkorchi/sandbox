# Execution repository

`openSandboxExecutionRepository()` is the process-isolation boundary for an application that must survive loss of the Node.js process which admitted a command. The repository belongs outside the untrusted workspace and must be available only to the trusted application account.

The caller supplies one stable `executionId` for one logical external effect. The repository binds that identity to the canonical digest of the complete run request. A concurrent or replacement caller using the same identity observes the existing execution; a different request is rejected. The repository never creates a second target for an existing identity.

```ts
import {
  LINUX_PROCESS_BASELINE_REQUIREMENTS,
  openSandboxExecutionRepository,
} from "@ismail-elkorchi/sandbox";

const executions = await openSandboxExecutionRepository({
  directory: "/private/application-state/sandbox-executions",
  maxRetainedOutputBytes: 8 * 1024 * 1024,
});

const prepared = await executions.prepare({
  executionId: "effect_01J...",
  run: {
    isolation: { kind: "process" },
    policy,
    requirements: LINUX_PROCESS_BASELINE_REQUIREMENTS,
    resources: { maxOutputBytes: 8 * 1024 * 1024 },
    process: {
      executable: "/usr/bin/git",
      args: ["status", "--porcelain=v2", "-z"],
      cwd: "/workspace",
      stdin: "closed",
      stdout: "pipe",
      stderr: "pipe",
    },
  },
}, { waitMs: 250 });

if (prepared.kind !== "prepared") throw new Error(`Preparation is ${prepared.kind}`);
// Present prepared.summary, prepared.enforcement, and both exact digests to the
// application authorization layer before issuing one-shot effect authority.
await executions.activate(prepared.executionId, prepared);
```

`activate()` acknowledges only after the execution host has durably consumed the exact authority. From that point the observation is in flight and can never return to `prepared`, including if the execution host is lost before it publishes a process identifier. Callers should continue inspecting transitional `preparing` or `running` observations until a terminal receipt or an explicit unknown outcome is available.

Output is retained as a checksum-linked, bounded byte stream. `inspect()` accepts `afterCursor` and `maxBytes`; `writeInput()`, `closeInput()`, and `terminate()` authenticate to the live execution host. A terminal receipt contains the native sandbox result, including enforcement, resource usage, violations, and cleanup.

## Durability boundary

The repository proves survival of **application-process termination**. A detached package-owned execution host continues supervising the native sandbox and publishes one terminal receipt. This does not claim transparent recovery from:

- execution-host termination;
- operating-system restart;
- power loss;
- storage truncation or checksum failure.

Those cases produce an explicit `unknown` observation. Callers must reconcile or ask for a decision; they must not replay an unsafe effect automatically. An expired identity is also explicit during its retention interval and cannot be admitted again under the same identity.

Sensitive environment values are transferred to the execution host over a private inherited descriptor and are not written into the repository. State records, output, authentication material, and receipts use private files under a private canonical directory. Completed output and receipts expire under bounded retention; expired identities are retained for a second bounded interval before removal.

Detached execution intentionally supports the process backend only. Hardware-VM execution has a different recovery authority and fails closed instead of falling back to host-process or process isolation.
