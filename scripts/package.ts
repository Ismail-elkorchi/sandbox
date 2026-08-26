import { mkdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { resolve } from "node:path";

const destination = resolve("release");
await mkdir(destination, { recursive: true });
for (const workspace of ["@ismail-elkorchi/sandbox", "@ismail-elkorchi/sandbox-hardware-vm"]) {
  await run("npm", ["pack", "--workspace", workspace, "--pack-destination", destination]);
}

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
