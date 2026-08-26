import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
await verifyManifest(resolve(repository, "native/manifest.json"), resolve(repository, "native"));
await verifyManifest(
  resolve(repository, "packages/sandbox/native/manifest.json"),
  resolve(repository, "packages/sandbox/native"),
);
await verifyManifest(
  resolve(repository, "packages/sandbox-hardware-vm/native/manifest.json"),
  resolve(repository, "packages/sandbox-hardware-vm"),
  true,
);

const imageRoot = resolve(repository, "packages/sandbox-hardware-vm/images/minimal-x64");
const imageManifest: unknown = JSON.parse(await readFile(resolve(imageRoot, "manifest.json"), "utf8"));
if (!isRecord(imageManifest) || !isRecord(imageManifest.kernel) || !isRecord(imageManifest.rootfs)) {
  throw new Error("VM image manifest has an invalid shape");
}
for (const [label, entry] of [["VM kernel", imageManifest.kernel], ["VM rootfs", imageManifest.rootfs]] as const) {
  if (typeof entry.path !== "string" || !/^[A-Za-z0-9._-]+$/u.test(entry.path)) {
    throw new Error(`${label} path is invalid`);
  }
  await verifyFile(resolve(imageRoot, entry.path), entry.sha256, label);
}

async function verifyManifest(manifestPath: string, base: string, vmLayout = false): Promise<void> {
  const manifest: unknown = JSON.parse(await readFile(manifestPath, "utf8"));
  if (!isRecord(manifest) || !isRecord(manifest.files)) throw new Error(`${manifestPath} has an invalid shape`);
  for (const [relativePath, expected] of Object.entries(manifest.files)) {
    if (relativePath.startsWith("/") || relativePath.split("/").includes("..")) {
      throw new Error(`${relativePath} is not a safe manifest path`);
    }
    const path = resolve(base, vmLayout && !relativePath.startsWith("images/") ? "native" : "", relativePath);
    await verifyFile(path, expected, relativePath);
  }
}

async function verifyFile(path: string, expected: unknown, label: string): Promise<void> {
  if (typeof expected !== "string" || !/^[a-f0-9]{64}$/u.test(expected)) {
    throw new Error(`${label} has an invalid digest`);
  }
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error(`${label} is not a regular package-owned file`);
  const actual = createHash("sha256").update(await readFile(path)).digest("hex");
  if (actual !== expected) throw new Error(`${label} failed SHA-256 verification`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
