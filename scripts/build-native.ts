import { createHash } from "node:crypto";
import { chmod, copyFile, lstat, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const debugBuild = process.env.SANDBOX_NATIVE_PROFILE === "debug";
const requestedTarget = process.env.SANDBOX_NATIVE_TARGET;
const defaultTarget = process.platform === "linux"
  ? `${process.arch === "arm64" ? "aarch64" : "x86_64"}-unknown-linux-musl`
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
  "-p", "sandbox-supervisor",
  "--bin", "sandbox-runtime",
  ...(target === undefined ? [] : ["--target", target]),
];
const buildEnvironment: Record<string, string> = target?.endsWith("-unknown-linux-musl")
  ? { [`CARGO_TARGET_${target.toUpperCase().replaceAll("-", "_")}_LINKER`]: "rust-lld" }
  : {};
if (nativePlatform === "windows" && !debugBuild) {
  buildEnvironment.RUSTFLAGS = `${process.env.RUSTFLAGS ?? ""} -C target-feature=+crt-static`.trim();
}
await run("cargo", buildArguments, buildEnvironment);

const executableSuffix = nativePlatform === "windows" ? ".exe" : "";
const destinationDirectory = resolve(repository, "native", `${nativePlatform}-${architecture}`);
const destinationName = `sandbox-runtime-${nativePlatform}-${architecture}${executableSuffix}`;
const destination = resolve(destinationDirectory, destinationName);
await mkdir(destinationDirectory, { recursive: true });
await copyFile(resolve(
  repository,
  "target",
  ...(target === undefined ? [] : [target]),
  debugBuild ? "debug" : "release",
  `sandbox-runtime${executableSuffix}`,
), destination);
await chmod(destination, 0o755);
if (nativePlatform === "macos") {
  await run("/usr/bin/codesign", ["--force", "--sign", "-", "--options", "runtime", destination], {});
}
const packageNativeRoot = resolve(repository, "packages", "sandbox", "native");
const packageDestinationDirectory = resolve(packageNativeRoot, `${nativePlatform}-${architecture}`);
await mkdir(packageDestinationDirectory, { recursive: true });
await copyFile(destination, resolve(packageDestinationDirectory, destinationName));
await chmod(resolve(packageDestinationDirectory, destinationName), 0o755);
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
  await copyFile(helper, resolve(packageDestinationDirectory, helperName));
  await chmod(resolve(packageDestinationDirectory, helperName), 0o755);
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

function classifyTarget(target: string): { platform: "linux" | "macos" | "windows"; architecture: "x64" | "arm64" } {
  const architecture = target.startsWith("x86_64-") ? "x64" : target.startsWith("aarch64-") ? "arm64" : undefined;
  const platform = target.includes("linux") ? "linux" : target.includes("apple-darwin") ? "macos" : target.includes("windows") ? "windows" : undefined;
  if (architecture === undefined || platform === undefined) throw new Error(`unsupported Rust target ${target}`);
  return { platform, architecture };
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
