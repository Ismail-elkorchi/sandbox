import { openSandboxExecutionRepository } from "../../dist/index.js";
import { baseOptions } from "../helpers.mjs";

const [repositoryDirectory, workspace] = process.argv.slice(2);
if (repositoryDirectory === undefined || workspace === undefined) process.exit(2);

const repository = await openSandboxExecutionRepository({ directory: repositoryDirectory });
const observation = await repository.admit({
  executionId: "caller-loss",
  run: {
    ...baseOptions({
      policy: {
        filesystem: {
          runtime: { kind: "system" },
          grants: [{ hostPath: workspace, targetPath: "/workspace", access: "read-write" }],
        },
        network: { mode: "none" },
        process: { hostProcesses: "deny", hostIpc: "deny" },
      },
    }),
    resources: { maxOutputBytes: 1024 * 1024 },
    process: {
      executable: "/bin/sh",
      args: ["-c", "sleep 0.2; printf completed > /workspace/completed; printf detached-output"],
      cwd: "/workspace",
      stdout: "pipe",
    },
  },
}, { waitMs: 100 });

if (observation.kind !== "running" && observation.kind !== "starting") {
  throw new Error(`Expected a live detached execution, received ${observation.kind}.`);
}
process.stdout.write("admitted\n", () => process.exit(0));
