# Detached execution repository

The execution repository durably binds one `executionId` to one exact run request. The request includes the selected isolation topology, explicit filesystem resources, scoped hard limits, tagged process paths, environment, and output requests.

```ts
const repository = await openSandboxExecutionRepository({ directory });
const request = {
  executionId: "job-42",
  run: {
    isolation: { kind: "process" },
    policy,
    requirements: {},
    resources: {
      output: { enforcement: "hard", scope: "process", value: 8 * 1024 * 1024 },
    },
    process: {
      executable: { space: "isolated", path: "/tools/program" },
      cwd: { space: "isolated", path: "/workspace" },
      stdout: "pipe",
    },
  },
};

const prepared = await repository.prepare(request);
if (prepared.kind === "prepared") {
  await authorize(prepared);
  await repository.activate(request.executionId, prepared);
}
const observation = await repository.inspect(request.executionId, { waitMs: 5_000 });
```

Detached runs require a process-scoped hard output limit. Preparation, activation, output cursors, receipts, and cleanup are persisted atomically. Recovery reconciles the bound implementation and prepared identities; it never prepares against another implementation. Incompatible schema records are rejected and left unchanged.

Cancelling a prepared execution acknowledges the durable terminal cancellation record. Once `terminate` resolves for that preparation, `forget` may remove it without a polling delay. Running process completion is published only after both output streams finish and all retained output writes are durable; the terminal cursor and hash cover the complete retained output.
