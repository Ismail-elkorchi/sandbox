import { rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { resolve } from "node:path";

await rm(resolve("packages/sandbox/dist"), { recursive: true, force: true });
await rm(resolve("packages/sandbox/tsconfig.tsbuildinfo"), { force: true });
await run("tsc", ["-b"]);
await run("tsc", ["-p", "scripts/tsconfig.json"]);

function run(command: string, arguments_: readonly string[]): Promise<void> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, arguments_, { stdio: "inherit" });
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"})`));
    });
  });
}
