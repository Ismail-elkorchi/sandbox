import { chmod, copyFile, mkdir, mkdtemp, rename, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { hydrateImageSources } from "./image-sources.ts";
import { publishNativePlatform } from "./native-artifacts.ts";
import { bundledImageManifestDigest } from "./native-image.ts";
import { tmpdir } from "node:os";
import { buildQemu } from "./build-qemu.ts";
import { fetchFirecracker } from "./firecracker-source.ts";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
await hydrateImageSources();

const buildProfile = process.env.SANDSURF_NATIVE_PROFILE ?? "debug";
if (buildProfile !== "debug" && buildProfile !== "release") throw new Error("SANDSURF_NATIVE_PROFILE must be debug or release");
const debugBuild = buildProfile === "debug";
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
  ...(nativePlatform === "macos" ? ["-p", "sandsurf-native", "--bin", "sandsurf-resource-broker"] : []),
  ...(target === undefined ? [] : ["--target", target]),
];
const buildEnvironment: Record<string, string | undefined> = target?.endsWith("-unknown-linux-musl")
  ? { [`CARGO_TARGET_${target.toUpperCase().replaceAll("-", "_")}_LINKER`]: "rust-lld" }
  : {};
if (["linux", "macos", "windows"].includes(nativePlatform)) {
  buildEnvironment.SANDSURF_BUNDLED_IMAGE_MANIFEST_DIGEST = await bundledImageManifestDigest(resolve(repository, "packages/sandsurf/images"), architecture);
  if (buildEnvironment.SANDSURF_BUNDLED_IMAGE_MANIFEST_DIGEST === undefined) {
    process.stdout.write(`No bundled ${architecture} OS: native host will report no default image. Imported machine images remain a separate capability.\n`);
  }
}
if (nativePlatform === "linux" && (target === undefined || target.endsWith("-unknown-linux-gnu"))) {
  const linuxTarget = target ?? `${process.arch === "x64" ? "x86_64" : "aarch64"}-unknown-linux-gnu`;
  buildEnvironment[`CARGO_TARGET_${linuxTarget.toUpperCase().replaceAll("-", "_")}_RUSTFLAGS`] = "-C target-feature=+crt-static";
}
if (nativePlatform === "windows" && !debugBuild) {
  buildEnvironment.RUSTFLAGS = `${process.env.RUSTFLAGS ?? ""} -C target-feature=+crt-static`.trim();
}
await run("cargo", buildArguments, buildEnvironment);

const executableSuffix = nativePlatform === "windows" ? ".exe" : "";
const platform = `${nativePlatform}-${architecture}`;
const stage = await mkdtemp(resolve(tmpdir(), "sandsurf-native-build-"));
try {
  const payload = resolve(stage, platform);
  await mkdir(payload);
  const destinationName = `sandsurf-host-${platform}${executableSuffix}`;
  const destination = resolve(payload, destinationName);
  await replaceArtifact(resolve(repository, "target", ...(target === undefined ? [] : [target]),
    debugBuild ? "debug" : "release", `sandsurf-host${executableSuffix}`), destination);
  if (nativePlatform === "linux") {
    await run("strip", ["--strip-debug", destination], {});
    await assertStaticElf(destination);
    await fetchFirecracker(payload, architecture as "x64" | "arm64");
    for (const name of ["network-boundary.nft", "sandsurf-network.service"]) {
      await replaceArtifact(resolve(repository, "vmm/linux", name), resolve(payload, name), 0o644);
    }
  }
  if (nativePlatform === "macos") {
    await run("/usr/bin/codesign", ["--force", "--sign", "-", "--options", "runtime", destination], {});
    const broker = resolve(payload, "sandsurf-resource-broker");
    await replaceArtifact(resolve(repository, "target", ...(target === undefined ? [] : [target]),
      debugBuild ? "debug" : "release", "sandsurf-resource-broker"), broker);
    await run("/usr/bin/codesign", ["--force", "--sign", "-", "--options", "runtime", broker], {});
  }
  let corresponding: string | undefined;
  if (nativePlatform === "macos" || nativePlatform === "windows") {
    if (architecture !== process.arch || nativePlatform !== (process.platform === "darwin" ? "macos" : "windows")) {
      throw new Error("QEMU runtime must be built on its native host architecture");
    }
    await buildQemu(payload);
    corresponding = resolve(stage, "qemu-source");
    await rename(resolve(payload, "qemu-source"), corresponding);
  }
  for (const root of [resolve(repository, "native"), resolve(repository, "packages/sandsurf/native")]) {
    await publishNativePlatform(root, platform, payload, corresponding);
  }
} finally {
  // Only this invocation's staged generated build, never machine storage.
  await rm(stage, { recursive: true, force: true });
}

function classifyTarget(target: string): { platform: "linux" | "macos" | "windows"; architecture: "x64" | "arm64" } {
  const architecture = target.startsWith("x86_64-") ? "x64" : target.startsWith("aarch64-") ? "arm64" : undefined;
  const platform = target.includes("linux") ? "linux" : target.includes("apple-darwin") ? "macos" : target.includes("windows") ? "windows" : undefined;
  if (architecture === undefined || platform === undefined) throw new Error(`unsupported Rust target ${target}`);
  return { platform, architecture };
}

async function replaceArtifact(source: string, destination: string, mode = 0o755): Promise<void> {
  const temporary = `${destination}.new-${process.pid}`;
  await rm(temporary, { force: true });
  try {
    await copyFile(source, temporary);
    await chmod(temporary, mode);
    await rename(temporary, destination);
  } finally {
    await rm(temporary, { force: true });
  }
}

function run(command: string, args: readonly string[], environment: Readonly<Record<string, string | undefined>>): Promise<void> {
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
