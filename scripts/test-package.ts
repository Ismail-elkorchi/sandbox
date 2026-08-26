import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const temporary = await mkdtemp(resolve(tmpdir(), "sandbox-package-test-"));
try {
  const core = await pack("@ismail-elkorchi/sandbox");
  const vm = await pack("@ismail-elkorchi/sandbox-hardware-vm");
  for (const tarball of [core, vm]) {
    const listing = await capture("tar", ["-tzf", tarball]);
    const paths = listing.trim().split("\n");
    if (paths.some((path) => path.includes("node_modules/") || path.includes("/target/") || path.endsWith(".tsbuildinfo"))) {
      throw new Error(`${tarball} contains development output`);
    }
    if (!paths.includes("package/package.json") || !paths.includes("package/dist/index.js") || !paths.includes("package/README.md") || !paths.includes("package/LICENSE")) {
      throw new Error(`${tarball} is missing package entry points`);
    }
  }
  const consumer = resolve(temporary, "consumer");
  await mkdir(consumer);
  await run("npm", ["init", "--yes"], consumer);
  await run("npm", ["install", "--ignore-scripts", core, vm], consumer);
  await run("node", ["--input-type=module", "--eval", "await import('@ismail-elkorchi/sandbox'); await import('@ismail-elkorchi/sandbox-hardware-vm')"], consumer);
  const lock = await readFile(resolve(consumer, "package-lock.json"), "utf8");
  if (lock.includes("node_modules/typescript")) throw new Error("consumer install contains development dependencies");
} finally {
  await rm(temporary, { recursive: true, force: true });
}

async function pack(workspace: string): Promise<string> {
  const output = await capture("npm", ["pack", "--json", "--workspace", workspace, "--pack-destination", temporary]);
  const parsed: unknown = JSON.parse(output);
  if (!Array.isArray(parsed) || parsed.length !== 1 || typeof parsed[0]?.filename !== "string") {
    throw new Error(`npm pack returned an invalid result for ${workspace}`);
  }
  return resolve(temporary, parsed[0].filename);
}

function run(command: string, arguments_: readonly string[], cwd = process.cwd()): Promise<void> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, arguments_, { cwd, stdio: "ignore" });
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"})`));
    });
  });
}

function capture(command: string, arguments_: readonly string[]): Promise<string> {
  return new Promise((resolveRun, rejectRun) => {
    const output: Buffer[] = [];
    const errors: Buffer[] = [];
    const child = spawn(command, arguments_, { stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.on("data", (chunk: Buffer) => output.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => errors.push(chunk));
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (code === 0) resolveRun(Buffer.concat(output).toString("utf8"));
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"}): ${Buffer.concat(errors).toString("utf8").slice(-4096)}`));
    });
  });
}
