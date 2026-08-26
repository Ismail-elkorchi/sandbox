import { createHash } from "node:crypto";
import { chmod, copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

if (process.platform !== "linux" || process.arch !== "x64") {
  throw new Error("the initial Firecracker runtime build requires Linux x64");
}
const native = resolve("packages/sandbox-hardware-vm/native/linux-x64");
const workspace = resolve(native, "empty-workspace.ext4");
const workspaceDigest = sha256(await readFile(workspace));
await run("cargo", [
  "build", "--release", "-p", "sandbox-vm-runtime",
  "--target", "x86_64-unknown-linux-musl",
], {
  SANDBOX_WORKSPACE_SHA256: workspaceDigest,
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER: "rust-lld",
});
await mkdir(native, { recursive: true });
const runtimeName = "sandbox-vm-runtime-linux-x64";
const runtime = resolve(native, runtimeName);
await copyFile(resolve("target/x86_64-unknown-linux-musl/release/sandbox-vm-runtime"), runtime);
await chmod(runtime, 0o755);
const firecrackerName = "firecracker-v1.16.1-x86_64";
const firecracker = resolve(native, firecrackerName);
const imageManifest = resolve("packages/sandbox-hardware-vm/images/minimal-x64/manifest.json");
const runtimeDigest = sha256(await readFile(runtime));
const firecrackerDigest = sha256(await readFile(firecracker));
if (firecrackerDigest !== "2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7") {
  throw new Error("Firecracker digest mismatch");
}
const imageManifestDigest = sha256(await readFile(imageManifest));
const descriptor = `${JSON.stringify({
  formatVersion: 1,
  kind: "hardware-vm",
  protocol: { minimumMajor: 1, maximumMajor: 1 },
  hosts: [{ platform: "linux", architecture: "x64" }],
  runtime: { path: runtimeName, sha256: runtimeDigest },
  vmm: { name: "Firecracker", version: "v1.16.1", path: firecrackerName, sha256: firecrackerDigest },
  workspaceTemplate: { path: "empty-workspace.ext4", sha256: workspaceDigest },
  imageTrust: { explicitLocal: true, bundledManifestDigests: [imageManifestDigest] },
}, null, 2)}\n`;
const descriptorPath = resolve(native, "extension.json");
await writeFile(descriptorPath, descriptor, { mode: 0o644 });
const files: Record<string, string> = {};
for (const [key, path] of [
  ["linux-x64/extension.json", descriptorPath],
  [`linux-x64/${runtimeName}`, runtime],
  [`linux-x64/${firecrackerName}`, firecracker],
  ["linux-x64/empty-workspace.ext4", workspace],
  ["images/minimal-x64/manifest.json", imageManifest],
] as const) files[key] = sha256(await readFile(path));
await writeFile(resolve("packages/sandbox-hardware-vm/native/manifest.json"), `${JSON.stringify({
  formatVersion: 1,
  buildId: "sandbox-hardware-vm-0.1.0",
  files,
}, null, 2)}\n`, { mode: 0o644 });

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function run(
  command: string,
  args: readonly string[],
  environment: Readonly<Record<string, string>> = {},
): Promise<void> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, { stdio: "inherit", env: { ...process.env, ...environment } });
    child.on("error", rejectRun);
    child.on("exit", (code, signal) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`${command} failed (${code ?? signal ?? "unknown"})`));
    });
  });
}
