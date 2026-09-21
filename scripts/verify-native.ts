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
const imagesRoot = resolve(repository, "packages/sandbox/images");
const imageIndexPath = resolve(imagesRoot, "manifest.json");
await verifyManifest(imageIndexPath, imagesRoot);
const imageIndex: unknown = JSON.parse(await readFile(imageIndexPath, "utf8"));
if (!isRecord(imageIndex) || !isRecord(imageIndex.files)) throw new Error("VM image index has an invalid shape");
const required = new Set((process.env.SANDSURF_REQUIRED_IMAGE_ARCHITECTURES ?? "").split(",").filter(Boolean));
for (const relative of Object.keys(imageIndex.files).sort()) {
  const match = /^minimal-(x64|arm64)\/manifest\.json$/u.exec(relative);
  if (match === null) throw new Error(`unsupported VM image index entry ${relative}`);
  const architecture = match[1]!;
  required.delete(architecture);
  const imageRoot = resolve(imagesRoot, `minimal-${architecture}`);
  const imageManifest: unknown = JSON.parse(await readFile(resolve(imageRoot, "manifest.json"), "utf8"));
  if (!isRecord(imageManifest) || imageManifest.formatVersion !== 2 || imageManifest.architecture !== architecture ||
      !isRecord(imageManifest.bootBundle) || !isRecord(imageManifest.bootBundle.kernel) ||
      !isRecord(imageManifest.bootBundle.bootstrap) || !isRecord(imageManifest.workload) ||
      !isRecord(imageManifest.workload.rootfs) || !isRecord(imageManifest.workload.stateTemplate)) {
    throw new Error(`${architecture} VM image manifest has an invalid shape`);
  }
  for (const [label, entry] of [
    ["VM kernel", imageManifest.bootBundle.kernel],
    ["trusted VM bootstrap", imageManifest.bootBundle.bootstrap],
    ["VM workload root", imageManifest.workload.rootfs],
    ["VM writable-state template", imageManifest.workload.stateTemplate],
  ] as const) {
    if (typeof entry.path !== "string" || !/^[A-Za-z0-9._-]+$/u.test(entry.path)) {
      throw new Error(`${architecture} ${label} path is invalid`);
    }
    await verifyFile(resolve(imageRoot, entry.path), entry.sha256, `${architecture} ${label}`);
  }
}
if (required.size !== 0) throw new Error(`required VM images are absent: ${[...required].join(", ")}`);

async function verifyManifest(manifestPath: string, base: string): Promise<void> {
  const manifest: unknown = JSON.parse(await readFile(manifestPath, "utf8"));
  if (!isRecord(manifest) || !isRecord(manifest.files)) throw new Error(`${manifestPath} has an invalid shape`);
  for (const [relativePath, expected] of Object.entries(manifest.files)) {
    if (relativePath.startsWith("/") || relativePath.split("/").includes("..")) {
      throw new Error(`${relativePath} is not a safe manifest path`);
    }
    const path = resolve(base, relativePath);
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
