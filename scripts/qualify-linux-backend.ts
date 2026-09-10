import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSandbox, type FilesystemAccess, type IsolatedFilesystemResource } from "../packages/sandbox/dist/index.js";

if (process.platform !== "linux") throw new Error("Linux implementation qualification requires a Linux host");

const host = (path: string) => ({ space: "host" as const, path });
const isolated = (path: string) => ({ space: "isolated" as const, path });
const readExecute: FilesystemAccess = {
  content: "read",
  directoryEntries: "read",
  metadata: "read",
  execution: "allow",
};
const runtimeCandidates: readonly (readonly [string, string, "executable" | "library" | "loader"])[] = [
  ["bin", "/bin", "executable"],
  ["usr-bin", "/usr/bin", "executable"],
  ["lib", "/lib", "library"],
  ["lib64", "/lib64", "loader"],
  ["usr-lib", "/usr/lib", "library"],
  ["usr-lib64", "/usr/lib64", "library"],
];
const runtimeResources: IsolatedFilesystemResource[] = runtimeCandidates
  .filter(([, path]) => existsSync(path))
  .map(([id, path, purpose]) => ({
  id,
  source: host(path),
  target: isolated(path),
  access: readExecute,
  purposes: [purpose as "executable" | "library" | "loader", "interpreter"],
  }));

const workspace = await mkdtemp(join(tmpdir(), "sandbox-qualification-"));
const outside = await mkdtemp(join(tmpdir(), "sandbox-qualification-outside-"));
const sandbox = await createSandbox();
try {
  await writeFile(join(workspace, "input"), "allowed");
  await writeFile(join(outside, "secret"), "denied");
  const policy = {
    filesystem: {
      kind: "isolated" as const,
      resources: [
        ...runtimeResources,
        {
          id: "workspace",
          source: host(workspace),
          target: isolated("/workspace"),
          access: {
            content: "read-write" as const,
            directoryEntries: "read-write" as const,
            metadata: "read-write" as const,
            execution: "deny" as const,
          },
          purposes: ["data" as const],
        },
      ],
    },
    network: { mode: "none" as const },
    process: {
      visibility: "session" as const,
      control: "session" as const,
      termination: { scope: "descendant-tree" as const, graceMs: 100 },
    },
    ipc: { visibility: "session" as const },
  };
  const support = await sandbox.probe({ isolation: { kind: "process" }, policy, requirements: {} });
  const implementation = support.implementations.find(
    (candidate) => candidate.identity.id === "linux-namespace-v1",
  );
  if (implementation?.eligibility.state !== "eligible") {
    const diagnostic = JSON.stringify({
      status: "unsupported-on-host",
      implementation: implementation ?? null,
    }, null, 2);
    process.stdout.write(`${diagnostic}\n`);
    throw new Error("linux-namespace-v1 required conformance cannot run on this host");
  } else {
    const result = await sandbox.run({
      isolation: { kind: "process" },
      policy,
      requirements: {},
      resources: {
        output: { enforcement: "hard", scope: "process", value: 1024 * 1024 },
      },
      process: {
        executable: isolated("/bin/sh"),
        args: [
          "-c",
          "test \"$(cat /workspace/input)\" = allowed && ! cat \"$1\" >/dev/null 2>&1 && printf qualified > /workspace/result",
          "sandbox",
          join(outside, "secret"),
        ],
        cwd: isolated("/workspace"),
      },
    });
    if (result.termination.reason !== "exit" || result.termination.code !== 0) {
      throw new Error(`linux-namespace-v1 execution failed: ${JSON.stringify(result.termination)}`);
    }
    if (await readFile(join(workspace, "result"), "utf8") !== "qualified" || !result.cleanup.completed) {
      throw new Error("linux-namespace-v1 did not preserve the authorized resource and cleanup contract");
    }
    process.stdout.write(`${JSON.stringify({
      status: "qualified",
      implementation: implementation.identity,
      guarantees: result.enforcement.guarantees.filter((fact) => fact.status === "satisfied").map((fact) => fact.id),
    }, null, 2)}\n`);
  }
} finally {
  await sandbox.dispose();
  await rm(workspace, { recursive: true, force: true });
  await rm(outside, { recursive: true, force: true });
}
