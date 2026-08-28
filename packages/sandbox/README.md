# @ismail-elkorchi/sandbox

Fail-closed sandbox execution for Node.js with prepared approval, exact executable/argument transport, explicit filesystem and network policy, hard resource controls, structured enforcement reports, and verified cleanup.

```sh
npm install @ismail-elkorchi/sandbox
```

```ts
import {
  createSandbox,
  LINUX_PROCESS_BASELINE_REQUIREMENTS,
} from "@ismail-elkorchi/sandbox";

const sandbox = await createSandbox();
try {
  const result = await sandbox.run({
    isolation: { kind: "process" },
    policy: {
      filesystem: { runtime: { kind: "system" }, grants: [] },
      network: { mode: "none" },
      process: { hostProcesses: "deny", hostIpc: "deny" },
    },
    requirements: LINUX_PROCESS_BASELINE_REQUIREMENTS,
    process: {
      executable: "/bin/printf",
      args: ["%s", "hello"],
      cwd: "/",
      stdout: "capture",
      stderr: "capture",
    },
  });
  console.log(result.stdout?.toString());
} finally {
  await sandbox.dispose();
}
```

Use `prepareRun()` instead of `run()` when another component must inspect and approve the Rust-produced summary, enforcement report, policy digest, and execution digest before starting a command.

Applications that need one isolated command to survive loss of the admitting Node.js process can use `openSandboxExecutionRepository()`. It binds one caller-provided execution identity to one exact request, retains bounded cursor-addressable output and one final receipt, and reports helper, operating-system, or storage loss as an explicit unknown outcome. See the [execution repository guide](https://github.com/Ismail-elkorchi/sandbox/blob/main/docs/execution-repository.md).

Supported backends include stable Linux namespace isolation and explicitly enabled experimental Windows AppContainer and macOS Seatbelt backends. The separate `@ismail-elkorchi/sandbox-hardware-vm` package provides the experimental Firecracker extension.

Full documentation: [github.com/Ismail-elkorchi/sandbox](https://github.com/Ismail-elkorchi/sandbox#readme)

Security policy: [SECURITY.md](https://github.com/Ismail-elkorchi/sandbox/blob/main/SECURITY.md)

Licensed under Apache-2.0.
