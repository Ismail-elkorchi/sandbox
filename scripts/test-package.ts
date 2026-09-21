import { copyFile, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const temporary = await mkdtemp(resolve(tmpdir(), "sandbox-package-test-"));
const originalUmask = process.platform === "win32" ? undefined : process.umask();
try {
  const core = await pack("sandsurf");
  const expectedImages = await packagedImagePaths();
  for (const tarball of [core]) {
    const listing = await capture("tar", ["-tzf", tarball]);
    const paths = listing.trim().split("\n");
    if (paths.some((path) => path.includes("node_modules/") || path.includes("/target/") || path.endsWith(".tsbuildinfo"))) {
      throw new Error(`${tarball} contains development output`);
    }
    if (!paths.includes("package/package.json") || !paths.includes("package/dist/index.js") || !paths.includes("package/README.md") || !paths.includes("package/LICENSE")) {
      throw new Error(`${tarball} is missing package entry points`);
    }
    for (const imagePath of expectedImages) {
      if (!paths.includes(imagePath)) throw new Error(`${tarball} is missing ${imagePath}`);
    }
    if (paths.some((path) => path.endsWith("minimal-rootfs.ext4") || path.endsWith("vmlinux-6.1.177"))) {
      throw new Error(`${tarball} contains a retired guest image artifact`);
    }
  }
  const consumer = resolve(temporary, "consumer");
  await mkdir(consumer);
  if (originalUmask !== undefined) process.umask(0o002);
  await run("npm", ["init", "--yes"], consumer);
  await run("npm", ["install", "--ignore-scripts", core], consumer);
  await run("node", ["--input-type=module", "--eval", "await import('sandsurf')"], consumer);
  await copyFile(resolve("scripts/package-consumer.mts"), resolve(consumer, "package-consumer.mts"));
  await run(process.execPath, [resolve("node_modules/typescript/bin/tsc"), "--strict", "--noEmit", "--module", "NodeNext", "--target", "ES2024",
    "--typeRoots", resolve("node_modules/@types"), "--types", "node", "package-consumer.mts"], consumer);
  const lock = await readFile(resolve(consumer, "package-lock.json"), "utf8");
  if (lock.includes("node_modules/typescript")) throw new Error("consumer install contains development dependencies");
} finally {
  if (originalUmask !== undefined) process.umask(originalUmask);
  await rm(temporary, { recursive: true, force: true });
}

async function packagedImagePaths(): Promise<readonly string[]> {
  const root = resolve("packages/sandbox/images");
  const index: unknown = JSON.parse(await readFile(resolve(root, "manifest.json"), "utf8"));
  if (!record(index) || !record(index.files)) throw new Error("guest image index is malformed");
  const paths = ["package/images/manifest.json"];
  const required = new Set((process.env.SANDSURF_REQUIRED_IMAGE_ARCHITECTURES ?? "").split(",").filter(Boolean));
  for (const relative of Object.keys(index.files).sort()) {
    const match = /^(minimal-(x64|arm64))\/manifest\.json$/u.exec(relative);
    if (match === null) throw new Error(`unsupported guest image index entry ${relative}`);
    required.delete(match[2]!);
    const manifest: unknown = JSON.parse(await readFile(resolve(root, relative), "utf8"));
    if (!record(manifest) || !record(manifest.bootBundle) || !record(manifest.bootBundle.kernel) ||
        !record(manifest.bootBundle.bootstrap) || !record(manifest.workload) ||
        !record(manifest.workload.rootfs) || !record(manifest.workload.stateTemplate)) {
      throw new Error(`${relative} is malformed`);
    }
    paths.push(`package/images/${relative}`);
    for (const artifact of [manifest.bootBundle.kernel, manifest.bootBundle.bootstrap, manifest.workload.rootfs, manifest.workload.stateTemplate]) {
      if (typeof artifact.path !== "string" || !/^[A-Za-z0-9._-]+$/u.test(artifact.path)) throw new Error(`${relative} has an unsafe artifact path`);
      paths.push(`package/images/${match[1]}/${artifact.path}`);
    }
  }
  if (required.size !== 0) throw new Error(`required packaged guest images are absent: ${[...required].join(", ")}`);
  return paths;
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
    const errors: Buffer[] = [];
    const child = spawn(command, arguments_, { cwd, stdio: ["ignore", "ignore", "pipe"] });
    child.stderr.on("data", (chunk: Buffer) => errors.push(chunk));
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"}): ${Buffer.concat(errors).toString("utf8").slice(-4096)}`));
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
