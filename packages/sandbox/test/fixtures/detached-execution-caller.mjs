import { openSandboxExecutionRepository } from "../../dist/index.js";
import {
  baseOptions,
  isolatedPath,
  isolatedPolicy,
  isolatedResource,
  readWriteAccess,
  runtimeResources,
} from "../helpers.mjs";

const [repositoryDirectory, workspace] = process.argv.slice(2);
if (repositoryDirectory === undefined || workspace === undefined) process.exit(2);

const repository = await openSandboxExecutionRepository({ directory: repositoryDirectory });
const request = {
  executionId: "caller-loss",
  run: {
    ...baseOptions({
      policy: {
        ...isolatedPolicy([
          ...runtimeResources(),
          isolatedResource("workspace", workspace, "/workspace", readWriteAccess(), ["data"]),
        ]),
      },
    }),
    resources: { output: { enforcement: "hard", scope: "process", value: 1024 * 1024 } },
    process: {
      executable: isolatedPath("/bin/sh"),
      args: ["-c", "sleep 0.2; printf completed > /workspace/completed; printf detached-output"],
      cwd: isolatedPath("/workspace"),
      stdout: "pipe",
    },
  },
};
const prepared = await repository.prepare(request, { waitMs: 2_000 });
if (prepared.kind !== "prepared") throw new Error(`Expected preparation, received ${prepared.kind}.`);
await repository.activate(request.executionId, prepared);
const observation = await repository.inspect(request.executionId, { waitMs: 100 });

if (observation.kind !== "running" && observation.kind !== "preparing") {
  throw new Error(`Expected a live detached execution, received ${observation.kind}.`);
}
process.stdout.write("admitted\n", () => process.exit(0));
