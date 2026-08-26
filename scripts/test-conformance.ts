import { spawn } from "node:child_process";

const child = spawn("node", ["--test", "packages/sandbox/test/linux-conformance.test.mjs"], {
  stdio: "inherit",
});
child.on("exit", (code) => process.exitCode = code ?? 1);
