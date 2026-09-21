import { createHash } from "node:crypto";
import { chmod, copyFile, lstat, mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const debugBuild = process.env.SANDSURF_NATIVE_PROFILE === "debug";
const requestedTarget = process.env.SANDSURF_NATIVE_TARGET || undefined;
// An explicit Linux target keeps target-only static-link flags away from host
// build scripts and proc macros.
const defaultTarget = process.platform === "linux"
  ? `${process.arch === "x64" ? "x86_64" : "aarch64"}-unknown-linux-gnu`
  : undefined;
const target = requestedTarget ?? defaultTarget;
const targetHost = target === undefined ? undefined : classifyTarget(target);
const architecture = targetHost?.architecture ?? process.arch;
const nativePlatform = targetHost?.platform
  ?? (process.platform === "win32" ? "windows" : process.platform === "darwin" ? "macos" : "linux");
if ((architecture !== "x64" && architecture !== "arm64") || !["linux", "macos", "windows"].includes(nativePlatform)) {
  throw new Error(`native builds do not support ${nativePlatform}-${architecture}`);
}
const buildArguments = [
  "build",
  ...(debugBuild ? [] : ["--release"]),
  "-p", "sandsurf-host",
  "--bin", "sandsurf-host",
  ...(target === undefined ? [] : ["--target", target]),
];
const buildEnvironment: Record<string, string> = target?.endsWith("-unknown-linux-musl")
  ? { [`CARGO_TARGET_${target.toUpperCase().replaceAll("-", "_")}_LINKER`]: "rust-lld" }
  : {};
if (["linux", "macos", "windows"].includes(nativePlatform)) {
  buildEnvironment.SANDSURF_BUNDLED_IMAGE_MANIFEST_DIGEST = await bundledImageManifestDigest(architecture);
}
if (nativePlatform === "linux" && !debugBuild && (target === undefined || target.endsWith("-unknown-linux-gnu"))) {
  const linuxTarget = target ?? `${process.arch === "x64" ? "x86_64" : "aarch64"}-unknown-linux-gnu`;
  buildEnvironment[`CARGO_TARGET_${linuxTarget.toUpperCase().replaceAll("-", "_")}_RUSTFLAGS`] = "-C target-feature=+crt-static";
}
if (nativePlatform === "windows" && !debugBuild) {
  buildEnvironment.RUSTFLAGS = `${process.env.RUSTFLAGS ?? ""} -C target-feature=+crt-static`.trim();
}
await run("cargo", buildArguments, buildEnvironment);

const executableSuffix = nativePlatform === "windows" ? ".exe" : "";
const destinationDirectory = resolve(repository, "native", `${nativePlatform}-${architecture}`);
const destinationName = `sandsurf-host-${nativePlatform}-${architecture}${executableSuffix}`;
const destination = resolve(destinationDirectory, destinationName);
await mkdir(destinationDirectory, { recursive: true });
await replaceArtifact(resolve(
  repository,
  "target",
  ...(target === undefined ? [] : [target]),
  debugBuild ? "debug" : "release",
  `sandsurf-host${executableSuffix}`,
), destination);
if (nativePlatform === "linux") await assertStaticElf(destination);
if (nativePlatform === "macos") {
  await run("/usr/bin/codesign", ["--force", "--sign", "-", "--options", "runtime", destination], {});
}
const packageNativeRoot = resolve(repository, "packages", "sandbox", "native");
const packageDestinationDirectory = resolve(packageNativeRoot, `${nativePlatform}-${architecture}`);
await mkdir(packageDestinationDirectory, { recursive: true });
await replaceArtifact(destination, resolve(packageDestinationDirectory, destinationName));
if (nativePlatform === "macos") {
  const helperName = `sandsurf-vz-helper-${architecture}`;
  const helper = resolve(destinationDirectory, helperName);
  await run("/usr/bin/swiftc", [
    resolve(repository, "native/macos/sandsurf-vz-helper.swift"),
    "-o", helper,
  ], {});
  await run("/usr/bin/codesign", [
    "--force", "--sign", "-", "--options", "runtime",
    "--entitlements", resolve(repository, "scripts/qualification/apple.entitlements"),
    helper,
  ], {});
  await replaceArtifact(helper, resolve(packageDestinationDirectory, helperName));
}
await writeManifest(resolve(repository, "native"));
await writeManifest(packageNativeRoot);

async function writeManifest(root: string): Promise<void> {
  const files: Record<string, string> = {};
  await collect("");
  await writeFile(resolve(root, "manifest.json"), `${JSON.stringify({
    formatVersion: 1,
    buildId: "sandsurf-native-0.1.0",
    files: Object.fromEntries(Object.entries(files).sort(([left], [right]) => left.localeCompare(right))),
  }, null, 2)}\n`, { mode: 0o644 });

  async function collect(relative: string): Promise<void> {
    for (const entry of await readdir(resolve(root, relative), { withFileTypes: true })) {
      const child = relative === "" ? entry.name : `${relative}/${entry.name}`;
      if (child === "manifest.json") continue;
      if (entry.isDirectory()) { await collect(child); continue; }
      const metadata = await lstat(resolve(root, child));
      if (!entry.isFile() || !metadata.isFile() || metadata.isSymbolicLink()) {
        throw new Error(`${child} is not a regular native artifact`);
      }
      files[child] = createHash("sha256").update(await readFile(resolve(root, child))).digest("hex");
    }
  }
}

async function bundledImageManifestDigest(guestArchitecture: "x64" | "arm64"): Promise<string> {
  const images = resolve(repository, "packages/sandbox/images");
  const index: unknown = JSON.parse(await readFile(resolve(images, "manifest.json"), "utf8"));
  if (!record(index) || !record(index.files)) throw new Error("bundled image index is malformed");
  const relative = `minimal-${guestArchitecture}/manifest.json`;
  const expected = index.files[relative];
  if (typeof expected !== "string" || !/^[a-f0-9]{64}$/u.test(expected)) {
    throw new Error(`bundled ${guestArchitecture} image identity is absent from the image index`);
  }
  const actual = createHash("sha256")
    .update(await readFile(resolve(images, relative)))
    .digest("hex");
  if (actual !== expected) throw new Error("bundled image manifest differs from its image index");
  return actual;
}

function classifyTarget(target: string): { platform: "linux" | "macos" | "windows"; architecture: "x64" | "arm64" } {
  const architecture = target.startsWith("x86_64-") ? "x64" : target.startsWith("aarch64-") ? "arm64" : undefined;
  const platform = target.includes("linux") ? "linux" : target.includes("apple-darwin") ? "macos" : target.includes("windows") ? "windows" : undefined;
  if (architecture === undefined || platform === undefined) throw new Error(`unsupported Rust target ${target}`);
  return { platform, architecture };
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function replaceArtifact(source: string, destination: string): Promise<void> {
  const temporary = `${destination}.new-${process.pid}`;
  await rm(temporary, { force: true });
  try {
    await copyFile(source, temporary);
    await chmod(temporary, 0o755);
    await rename(temporary, destination);
  } finally {
    await rm(temporary, { force: true });
  }
}

function run(command: string, args: readonly string[], environment: Readonly<Record<string, string>>): Promise<void> {
  return new Promise<void>((resolveRun, rejectRun) => {
    const child = spawn(command, args, { cwd: repository, stdio: "inherit", env: { ...process.env, ...environment } });
    child.on("error", rejectRun);
    child.on("exit", (code, signal) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"})`));
    });
  });
}

function assertStaticElf(path: string): Promise<void> {
  return new Promise<void>((resolveCheck, rejectCheck) => {
    const output: Buffer[] = [];
    const child = spawn("readelf", ["--program-headers", path], { stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.on("data", (chunk: Buffer) => output.push(chunk));
    child.once("error", rejectCheck);
    child.once("exit", (code, signal) => {
      if (code !== 0 || signal !== null) rejectCheck(new Error(`native ELF inspection failed (${code ?? signal ?? "unknown"})`));
      else if (Buffer.concat(output).toString("utf8").includes(" INTERP ")) rejectCheck(new Error("the Linux Sandsurf host must be statically linked for confined VMM launch"));
      else resolveCheck();
    });
  });
}
