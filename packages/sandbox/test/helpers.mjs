import { existsSync, realpathSync } from "node:fs";
import { createSandbox } from "../dist/index.js";

export const hostPath = (path) => ({ space: "host", path });
export const isolatedPath = (path) => ({ space: "isolated", path });

export function readAccess(execution = "deny") {
  return { content: "read", directoryEntries: "read", metadata: "read", execution };
}

export function readWriteAccess(execution = "deny") {
  return {
    content: "read-write",
    directoryEntries: "read-write",
    metadata: "read-write",
    execution,
  };
}

export function isolatedResource(id, source, target, access = readAccess(), purposes = ["data"]) {
  return {
    id,
    source: hostPath(source),
    target: isolatedPath(target),
    access,
    purposes,
  };
}

export function hostResource(id, path, access = readAccess(), purposes = ["data"]) {
  return { id, path: hostPath(path), access, purposes };
}

export function runtimeResources() {
  const candidates = [
    ["runtime-bin", "/bin", "executable"],
    ["runtime-usr-bin", "/usr/bin", "executable"],
    ["runtime-lib", "/lib", "library"],
    ["runtime-lib64", "/lib64", "loader"],
    ["runtime-usr-lib", "/usr/lib", "library"],
    ["runtime-usr-lib64", "/usr/lib64", "library"],
  ];
  return candidates
    .filter(([, source]) => existsSync(source))
    .map(([id, source, purpose]) =>
      isolatedResource(id, source, source, readAccess("allow"), [purpose, "interpreter"]));
}

export function isolatedPolicy(resources = runtimeResources(), overrides = {}) {
  return {
    filesystem: {
      kind: "isolated",
      resources,
      ...(overrides.masks === undefined ? {} : { masks: overrides.masks }),
      ...(overrides.privateHome === undefined ? {} : { privateHome: overrides.privateHome }),
      ...(overrides.temporary === undefined ? {} : { temporary: overrides.temporary }),
    },
    network: overrides.network ?? { mode: "none" },
    process: overrides.process ?? {
      visibility: "session",
      control: "session",
      termination: { scope: "descendant-tree", graceMs: 100 },
    },
    ipc: overrides.ipc ?? { visibility: "session" },
  };
}

export function hostPolicy(resources, overrides = {}) {
  return {
    filesystem: { kind: "host", resources },
    network: overrides.network ?? { mode: "none" },
    process: overrides.process ?? {
      visibility: "host",
      control: "session",
      termination: { scope: "descendant-tree", graceMs: 100 },
    },
    ipc: overrides.ipc ?? { visibility: "host" },
  };
}

export function baseOptions(overrides = {}) {
  return {
    isolation: { kind: "process" },
    policy: isolatedPolicy(),
    requirements: {},
    ...overrides,
  };
}

export function shellProcess(args = ["-c", "exit 0"], overrides = {}) {
  const shell = realpathSync("/bin/sh");
  const executable = shell.startsWith("/usr/bin/") ? shell : "/bin/sh";
  return {
    executable: isolatedPath(executable),
    args,
    cwd: isolatedPath("/"),
    ...overrides,
  };
}

export async function linuxImplementationEligible(options = baseOptions()) {
  if (process.platform !== "linux") return false;
  const sandbox = await createSandbox();
  try {
    const support = await sandbox.probe({
      isolation: options.isolation,
      policy: options.policy,
      requirements: options.requirements,
      resources: options.resources,
    });
    return support.implementations.some(
      (implementation) => implementation.identity.id === "linux-namespace-v1"
        && implementation.eligibility.state === "eligible",
    );
  } finally {
    await sandbox.dispose();
  }
}

export async function withSandbox(operation) {
  const sandbox = await createSandbox();
  try {
    return await operation(sandbox);
  } finally {
    await sandbox.dispose();
  }
}
