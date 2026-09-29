import { copyFile, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const temporary = await mkdtemp(resolve(tmpdir(), "machine-package-test-"));
const npmCli = requiredEnvironment("npm_execpath");
const originalUmask = process.platform === "win32" ? undefined : process.umask();
try {
  const core = await pack("sandsurf");
  const expectedImages = await packagedImagePaths();
  for (const tarball of [core]) {
    const listing = await capture("tar", ["-tzf", tarball]);
    const paths = listing.trim().split(/\r?\n/u).map((path) => path.replaceAll("\\", "/"));
    if (paths.some((path) => path.includes("node_modules/") || path.includes("/target/") || path.endsWith(".tsbuildinfo"))) {
      throw new Error(`${tarball} contains development output`);
    }
    if (!paths.includes("package/package.json") || !paths.includes("package/dist/index.js") || !paths.includes("package/README.md") || !paths.includes("package/LICENSE")) {
      throw new Error(`${tarball} is missing package entry points`);
    }
    for (const imagePath of expectedImages) {
      if (!paths.includes(imagePath)) throw new Error(`${tarball} is missing ${imagePath}`);
    }
    if (paths.some((path) => /(?:minimal-|trusted-bootstrap|development-workload|empty-workspace)/u.test(path))) {
      throw new Error(`${tarball} contains a retired guest image artifact`);
    }
  }
  const consumer = resolve(temporary, "consumer");
  await mkdir(consumer);
  if (originalUmask !== undefined) process.umask(0o002);
  await run(process.execPath, [npmCli, "init", "--yes"], consumer);
  await run(process.execPath, [npmCli, "install", "--ignore-scripts", core], consumer);
  await run(process.execPath, ["--input-type=module", "--eval", `
    import assert from "node:assert/strict";
    import { Sandsurf } from "sandsurf";
    import { NativeHostClient } from "./node_modules/sandsurf/dist/native-host.js";
    const directory = ${JSON.stringify(resolve(temporary, "installed-native-state"))};
    let host = await Sandsurf.open({ directory, authorizer: () => true });
    try {
      const before = await host.inspect();
      assert.ok(before.defaultImageDigest);
      const secret = await host.secrets.put("installed-binary-secret", Buffer.alloc(1024 ** 2, 255), { operationId: "installed-put" });
      assert.equal(secret.bytes, 1024 ** 2);
      await host.close();
      host = await Sandsurf.open({ directory, service: "connect" });
      assert.equal((await host.inspect()).hostId, before.hostId);
      const retained = await host.operations.get("installed-put");
      assert.equal(retained.kind, "secret-put");
      assert.equal(retained.value.secret.version, secret.version);
      assert.equal((await host.machines.list()).length, 0);
    } finally {
      await host.close();
      await (await NativeHostClient.open(directory)).stopService();
    }
  `], consumer);
  await copyFile(resolve("scripts/package-consumer.mts"), resolve(consumer, "package-consumer.mts"));
  await run(process.execPath, [resolve("node_modules/typescript/bin/tsc"), "--strict", "--noEmit", "--module", "NodeNext", "--target", "ES2024",
    "--typeRoots", resolve("node_modules/@types"), "--types", "node", "package-consumer.mts"], consumer);
  const lock = await readFile(resolve(consumer, "package-lock.json"), "utf8");
  if (lock.includes("node_modules/typescript")) throw new Error("consumer install contains development dependencies");
  if (process.env.SANDSURF_KVM_TEST === "1") {
    if (process.platform !== "linux" || process.arch !== "x64") throw new Error("installed KVM qualification requires a Linux x64 host");
    await run(process.execPath, ["--test", "--test-concurrency=1", resolve("packages/sandsurf/test/kvm-environment.test.mjs")], consumer, {
      SANDSURF_TEST_PACKAGE_ROOT: resolve(consumer, "node_modules/sandsurf"),
      SANDSURF_LOCAL_IMAGE_MANIFEST: resolve(consumer, "node_modules/sandsurf/images/development-x64/manifest.json"),
    });
  }
} finally {
  if (originalUmask !== undefined) process.umask(originalUmask);
  await rm(temporary, { recursive: true, force: true });
}

async function packagedImagePaths(): Promise<readonly string[]> {
  const root = resolve("packages/sandsurf/images");
  const index: unknown = JSON.parse(await readFile(resolve(root, "manifest.json"), "utf8"));
  if (!record(index) || !record(index.files)) throw new Error("guest image index is malformed");
  const paths = ["package/images/manifest.json"];
  const required = new Set((process.env.SANDSURF_REQUIRED_IMAGE_ARCHITECTURES ?? "").split(",").filter(Boolean));
  for (const relative of Object.keys(index.files).sort()) {
    const match = /^(development-(x64|arm64))\/manifest\.json$/u.exec(relative);
    if (match === null) throw new Error(`unsupported guest image index entry ${relative}`);
    required.delete(match[2]!);
    const manifest: unknown = JSON.parse(await readFile(resolve(root, relative), "utf8"));
    if (!record(manifest) || manifest.id !== "sandsurf-development" || manifest.version !== "3.24.2" ||
        !record(manifest.bootBundle) || !record(manifest.bootBundle.kernel) ||
        manifest.formatVersion !== 3 || !record(manifest.system) ||
        !record(manifest.system.rootfs) ||
        !record(manifest.system.provenance) || !record(manifest.system.provenance.materials)) {
      throw new Error(`${relative} is malformed`);
    }
    paths.push(`package/images/${relative}`);
    for (const artifact of [manifest.bootBundle.kernel, manifest.system.rootfs]) {
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
  const output = await capture(process.execPath, [npmCli, "pack", "--json", "--workspace", workspace, "--pack-destination", temporary]);
  const parsed: unknown = JSON.parse(output);
  if (!Array.isArray(parsed) || parsed.length !== 1 || typeof parsed[0]?.filename !== "string") {
    throw new Error(`npm pack returned an invalid result for ${workspace}`);
  }
  return resolve(temporary, parsed[0].filename);
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined) throw new Error(`${name} is required for package verification`);
  return value;
}

function run(command: string, arguments_: readonly string[], cwd = process.cwd(), environment: Readonly<Record<string, string>> = {}): Promise<void> {
  return new Promise((resolveRun, rejectRun) => {
    let output = "";
    let errors = "";
    const child = spawn(command, arguments_, { cwd, env: { ...process.env, ...environment }, stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.on("data", (chunk: Buffer) => { output = (output + chunk.toString("utf8")).slice(-4096); });
    child.stderr.on("data", (chunk: Buffer) => { errors = (errors + chunk.toString("utf8")).slice(-4096); });
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"}): ${output}\n${errors}`));
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
