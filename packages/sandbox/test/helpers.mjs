import { createSandbox } from "../dist/index.js";

export function baseOptions(overrides = {}) {
  return {
    isolation: { kind: "process" },
    policy: {
      filesystem: {
        runtime: { kind: "system" },
        grants: [],
      },
      network: { mode: "none" },
      process: { hostProcesses: "deny", hostIpc: "deny" },
    },
    requirements: {
      boundary: "os-process",
      required: [
        "runtime.setup-before-exec",
        "runtime.no-ambient-environment",
        "runtime.no-ambient-handles",
        "runtime.executable-identity-bound",
        "filesystem.grant-roots-identity-bound",
        "filesystem.read-confined",
        "filesystem.content-write-confined",
        "filesystem.namespace-mutation-confined",
        "filesystem.metadata-mutation-confined",
        "filesystem.host-user-data-hidden",
        "network.no-external-connect",
        "network.no-external-listen",
        "network.no-host-loopback",
        "process.host-enumeration-denied",
        "process.host-control-denied",
        "process.complete-tree-termination",
        "resource.wall-time-hard",
        "resource.output-hard",
        "resource.open-files-hard",
        "resource.single-file-size-hard",
      ],
    },
    ...overrides,
  };
}

export async function withSandbox(operation) {
  const sandbox = await createSandbox();
  try {
    return await operation(sandbox);
  } finally {
    await sandbox.dispose();
  }
}
