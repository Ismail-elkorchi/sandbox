# Getting started

## Requirements

- Node.js 24 or newer.
- A supported host backend.
- For the stable Linux backend: functional user, mount, PID, IPC, UTS, and network namespaces; Landlock; seccomp; and the other mechanisms returned by the probe.
- For Firecracker: Linux x64, KVM access, and the hardware-VM extension package.

Install the process package:

```sh
npm install @ismail-elkorchi/sandbox
```

## Probe before offering a feature

```ts
import { createSandbox } from "@ismail-elkorchi/sandbox";

const sandbox = await createSandbox();
try {
  const support = await sandbox.probe({ isolation: "process" });
  console.dir(support, { depth: null });
} finally {
  await sandbox.dispose();
}
```

A platform name alone does not establish availability. The native runtime performs functional checks and reports unavailable mechanisms. Preparation repeats the checks needed for the exact policy and fails before execution when a required guarantee cannot be established.

## Prepared one-shot runs

Use `prepareRun()` whenever another component or person approves commands:

```ts
const prepared = await sandbox.prepareRun(options);

await authorize({
  summary: prepared.summary,
  enforcement: prepared.enforcement,
  policyDigest: prepared.policyDigest,
  executionDigest: prepared.executionDigest,
  expiresAtMs: prepared.expiresAtMs,
});

const process = await prepared.start({
  policyDigest: prepared.policyDigest,
  executionDigest: prepared.executionDigest,
});
const result = await process.wait();
```

Approve the values returned by the prepared object, not a digest independently reconstructed from the original request. A prepared object expires, is consumed by its first start attempt, and can be cancelled before use.

`sandbox.run(options)` performs prepare and start with the returned digests automatically. It is useful when the caller itself is the authorization boundary.

## Sessions

A session retains one immutable policy and runs processes sequentially:

```ts
const prepared = await sandbox.prepareSession(sessionOptions);
const session = await prepared.activate({ policyDigest: prepared.policyDigest });

try {
  const first = await session.run({
    executable: "/bin/printf",
    args: ["%s", "first"],
    cwd: "/",
    stdout: "capture",
  });
  const second = await session.run({
    executable: "/bin/printf",
    args: ["%s", "second"],
    cwd: "/",
    stdout: "capture",
  });
  console.log(first.stdout?.toString(), second.stdout?.toString());
} finally {
  await session.close();
}
```

Each session process has its own execution digest. The initial protocol permits only one active target process per session.

## Streams and cancellation

Choose `pipe`, `capture`, or `discard` for stdout and stderr. Captured bytes are available on the final result. Piped streams use protocol credits so a slow Node consumer cannot cause unbounded runtime allocation.

When stdin is `pipe`, write only after `prepare.start()` returns a process. Call `process.terminate()` or abort the process signal to cancel. Wall-time and termination controls are independent of stdin and output backpressure.

## Results

Always inspect:

- `termination`: structured exit, signal, timeout, cancellation, limit, policy, or runtime-failure attribution.
- `enforcement`: the exact mechanisms and caveats for this run.
- `violations`: bounded structured policy events; generic target stderr is never treated as evidence.
- `usage`: available resource and network accounting.
- `cleanup`: confirmed cleanup state and every cleanup failure.
- `artifacts` and `changeSets`: explicit VM outputs when requested.

A normal target exit does not imply cleanup success. Treat `cleanup.completed === false` as an operational failure.

## Disposal

Close sessions and call `sandbox.dispose()` in `finally`. Disposal is idempotent and waits for owned runtime shutdown, with forced termination when the graceful protocol deadline is exceeded.
