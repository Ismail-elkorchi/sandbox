import { copyFile, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { packageArchive } from "./package-archive.ts";

const temporary = await mkdtemp(resolve(process.platform === "linux" ? "/var/tmp" : tmpdir(), "machine-package-test-"));
const npmCli = requiredEnvironment("npm_execpath");
const originalUmask = process.platform === "win32" ? undefined : process.umask();
try {
  const core = await packageArchive(resolve("packages/sandsurf"), temporary, npmCli);
  const expectedImages = await packagedImagePaths();
  const expectedNative = await packagedNativePaths();
  for (const tarball of [core]) {
    const listing = await capture("tar", ["-tzf", tarball]);
    const paths = listing.trim().split(/\r?\n/u).map((path) => path.replaceAll("\\", "/"));
    if (paths.some((path) => path.includes("node_modules/") || path.includes("/target/") || path.endsWith(".tsbuildinfo"))) {
      throw new Error(`${tarball} contains development output`);
    }
    if (!paths.includes("package/package.json") || !paths.includes("package/dist/index.js") || !paths.includes("package/README.md") || !paths.includes("package/LICENSE")) {
      throw new Error(`${tarball} is missing package entry points`);
    }
    for (const payloadPath of [...expectedImages, ...expectedNative]) {
      if (!paths.includes(payloadPath)) throw new Error(`${tarball} is missing ${payloadPath}`);
    }
    if (paths.some((path) => /(?:minimal-|trusted-bootstrap|development-workload|empty-workspace)/u.test(path))) {
      throw new Error(`${tarball} contains a retired guest image artifact`);
    }
    if (paths.some((path) => /\.(?:ext4|vhdx)$/u.test(path))) throw new Error("package contains unpacked machine disks");
  }
  const consumer = resolve(temporary, "consumer");
  await mkdir(consumer);
  if (originalUmask !== undefined) process.umask(0o002);
  await run(process.execPath, [npmCli, "init", "--yes"], consumer);
  await run(process.execPath, [npmCli, "install", "--ignore-scripts", core], consumer);
  const installedDirectory = process.env.SANDSURF_PACKAGE_TEST_DIRECTORY ?? resolve(temporary, "installed-native-state");
  const slot = (await capture(process.execPath, [resolve(consumer, "node_modules/sandsurf/dist/cli.js"), "storage-path", "--directory", installedDirectory, "--machine", "installed-storage-slot"])).trim();
  if (slot !== resolve(installedDirectory, "machines", "id-" + createHash("sha256").update("installed-storage-slot").digest("hex"))) throw new Error("installed CLI derived an inconsistent machine storage address");
  await run(process.execPath, ["--input-type=module", "--eval", `
    import assert from "node:assert/strict";
    import { Sandsurf } from "sandsurf";
    import { NativeHostClient } from "./node_modules/sandsurf/dist/native-host.js";
    const directory = ${JSON.stringify(installedDirectory)};
    let host = await Sandsurf.open({ directory, authorizer: () => true });
    try {
      const before = await host.inspect();
      assert.ok(before.defaultImageDigest);
      assert.equal(before.guestPower.reboot.kind, process.platform === "linux" && process.arch === "x64" ? "supported" : "unsupported");
      assert.equal(before.console.kind, "supported");
      assert.equal(before.guestPower.shutdown.kind, process.platform === "linux" && process.arch === "x64" ? "unsupported" : "supported");
      const nativeImport = {
        manifestPath: ${JSON.stringify(resolve(consumer, "node_modules/sandsurf/images"))} + "/development-" + (before.guestArchitecture === "arm64" ? "arm64" : "x64") + "/manifest.json",
        manifestDigest: before.defaultImageDigest,
        operationId: "installed-native-image",
      };
      const nativeImage = before.imageWorkers.kind === "supported"
        ? await host.images.importNative(nativeImport) : undefined;
      if (nativeImage !== undefined) assert.equal(nativeImage.id, before.defaultImageDigest);
      else await assert.rejects(host.images.importNative(nativeImport), (error) => error.category === "unsupported");
      const secret = await host.secrets.put("installed-binary-secret", Buffer.alloc(1024 ** 2, 255), { operationId: "installed-put" });
      assert.equal(secret.bytes, 1024 ** 2);
      await host.close();
      host = await Sandsurf.open({ directory, service: "connect", authorizer: () => true });
      assert.equal((await host.inspect()).hostId, before.hostId);
      if (nativeImage !== undefined) {
        assert.equal((await host.images.importNative(nativeImport)).id, nativeImage.id);
        assert.equal((await host.images.get(nativeImage.id)).id, nativeImage.id);
      }
      const retained = await host.operations.get("installed-put");
      assert.equal(retained.id, "installed-put");
      const operation = await retained.inspect();
      assert.equal(operation.owner, "host-authority");
      assert.equal(operation.observation.kind, "secret-put");
      assert.equal(operation.observation.secret.version, secret.version);
      assert.equal((await host.machines.list()).length, 0);
    } finally {
      await host.close();
      const administration = await NativeHostClient.open(directory);
      await administration.stopService();
      await administration.stopSupervisor();
    }
  `], consumer);
  await copyFile(resolve("scripts/package-consumer.mts"), resolve(consumer, "package-consumer.mts"));
  process.stdout.write("Installed native API/CLI checks passed; validating consumer declarations.\n");
  await run(process.execPath, [resolve("node_modules/typescript/bin/tsc"), "--strict", "--noEmit", "--module", "NodeNext", "--target", "ES2024",
    "--typeRoots", resolve("node_modules/@types"), "--types", "node", "package-consumer.mts"], consumer, { NODE_OPTIONS: "--max-old-space-size=256" });
  const lock = await readFile(resolve(consumer, "package-lock.json"), "utf8");
  if (lock.includes("node_modules/typescript")) throw new Error("consumer install contains development dependencies");
  const hardwareTests: string[] = [];
  if (process.env.SANDSURF_KVM_TEST === "1") hardwareTests.push(resolve("packages/sandsurf/test/kvm-environment.test.mjs"));
  if (process.env.SANDSURF_KVM_NETWORK_TEST === "1") hardwareTests.push(resolve("packages/sandsurf/test/native-network-hardware.test.mjs"));
  if (process.env.SANDSURF_SERVICE_MANAGER_TEST === "1") hardwareTests.push(resolve("packages/sandsurf/test/systemd-machine.test.mjs"));
  if (process.env.SANDSURF_LINUX_QUALIFICATION === "1") hardwareTests.push(resolve("packages/sandsurf/test/linux-workloads.test.mjs"));
  if (hardwareTests.length !== 0) {
    if (process.platform !== "linux" || process.arch !== "x64") throw new Error("installed Linux VM qualification requires a Linux x64 host");
    await run(process.execPath, ["--test", "--test-concurrency=1", ...hardwareTests], consumer, {
      SANDSURF_TEST_PACKAGE_ROOT: resolve(consumer, "node_modules/sandsurf"),
      SANDSURF_LOCAL_IMAGE_MANIFEST: undefined,
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
        manifest.formatVersion !== 1 || !record(manifest.system) ||
        !record(manifest.system.rootfs) ||
        !record(manifest.system.provenance) || !record(manifest.system.provenance.materials)) {
      throw new Error(`${relative} is malformed`);
    }
    paths.push(`package/images/${relative}`);
    if (!record(manifest.bootBundle.initramfs)) throw new Error(`${relative} lacks the distribution initramfs`);
    const artifacts = [manifest.bootBundle.kernel, manifest.bootBundle.initramfs];
    const disks = [manifest.system.rootfs];
    if (match[2] === "x64") {
      if (!record(manifest.platformArtifacts) || !record(manifest.platformArtifacts.windowsX64)) {
        throw new Error(`${relative} lacks Windows VM artifacts`);
      }
      const windows = manifest.platformArtifacts.windowsX64;
      if (!record(windows.kernel) || !record(windows.system)) throw new Error(`${relative} has malformed Windows artifacts`);
      artifacts.push(windows.kernel);
      disks.push(windows.system);
    }
    for (const artifact of artifacts) {
      if (typeof artifact.path !== "string" || !/^[A-Za-z0-9._-]+$/u.test(artifact.path)) throw new Error(`${relative} has an unsafe artifact path`);
      paths.push(`package/images/${match[1]}/${artifact.path}`);
    }
    for (const disk of disks) {
      if (typeof disk.path !== "string" || !/^[A-Za-z0-9._-]+$/u.test(disk.path)) throw new Error(`${relative} has an unsafe disk path`);
      paths.push(`package/images/${match[1]}/${disk.path}.gz`);
    }
  }
  if (required.size !== 0) throw new Error(`required packaged guest images are absent: ${[...required].join(", ")}`);
  return paths;
}

async function packagedNativePaths(): Promise<readonly string[]> {
  const index: unknown = JSON.parse(await readFile(resolve("packages/sandsurf/native/manifest.json"), "utf8"));
  if (!record(index) || index.formatVersion !== 1 || index.buildId !== "sandsurf-native-1.0.0" || !record(index.files)) {
    throw new Error("native package index is malformed");
  }
  const paths = ["package/native/manifest.json"];
  const required = new Set((process.env.SANDSURF_REQUIRED_NATIVE_PLATFORMS ?? "").split(",").filter(Boolean));
  for (const [relative, digest] of Object.entries(index.files)) {
    const match = /^((?:linux|macos|windows)-(?:x64|arm64))\/[A-Za-z0-9._-]+$/u.exec(relative);
    if (match === null || typeof digest !== "string" || !/^[a-f0-9]{64}$/u.test(digest)) throw new Error(`invalid native package entry ${relative}`);
    required.delete(match[1]!);
    paths.push(`package/native/${relative}`);
  }
  if (required.size !== 0) throw new Error(`required native platforms are absent: ${[...required].join(", ")}`);
  return paths;
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined) throw new Error(`${name} is required for package verification`);
  return value;
}

function run(command: string, arguments_: readonly string[], cwd = process.cwd(), environment: Readonly<Record<string, string | undefined>> = {}): Promise<void> {
  return new Promise((resolveRun, rejectRun) => {
    let output = "";
    let errors = "";
    const child = spawn(command, arguments_, { cwd, env: { ...process.env, ...environment }, stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.on("data", (chunk: Buffer) => { output = (output + chunk.toString("utf8")).slice(-4096); process.stdout.write(chunk); });
    child.stderr.on("data", (chunk: Buffer) => { errors = (errors + chunk.toString("utf8")).slice(-4096); process.stderr.write(chunk); });
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
