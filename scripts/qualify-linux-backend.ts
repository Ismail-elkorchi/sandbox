import {
  LINUX_PROCESS_BASELINE_REQUIREMENTS,
  createSandbox,
} from "../packages/sandbox/dist/index.js";

if (process.platform !== "linux") throw new Error("Linux backend qualification requires a Linux host");

const sandbox = await createSandbox();
try {
  const support = await sandbox.probe({
    isolation: "process",
    required: LINUX_PROCESS_BASELINE_REQUIREMENTS.required,
  });
  const backend = support.backends.find((candidate) => candidate.id === "linux-namespace-v1");
  if (!backend?.available) {
    throw new Error(`linux-namespace-v1 failed functional qualification: ${JSON.stringify(backend ?? null)}`);
  }
  process.stdout.write(`${JSON.stringify({
    status: "qualified",
    backend: backend.id,
    required: LINUX_PROCESS_BASELINE_REQUIREMENTS.required,
  }, null, 2)}\n`);
} finally {
  await sandbox.dispose();
}
