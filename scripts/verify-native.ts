import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
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
for (const entry of await readdir(imagesRoot, { withFileTypes: true })) {
  if (entry.name.startsWith("minimal-")) throw new Error(`retired image directory remains packaged: ${entry.name}`);
}
const required = new Set((process.env.SANDSURF_REQUIRED_IMAGE_ARCHITECTURES ?? "").split(",").filter(Boolean));
for (const relative of Object.keys(imageIndex.files).sort()) {
  const match = /^development-(x64|arm64)\/manifest\.json$/u.exec(relative);
  if (match === null) throw new Error(`unsupported VM image index entry ${relative}`);
  const architecture = match[1]!;
  required.delete(architecture);
  const imageRoot = resolve(imagesRoot, `development-${architecture}`);
  const imageManifest: unknown = JSON.parse(await readFile(resolve(imageRoot, "manifest.json"), "utf8"));
  if (!isRecord(imageManifest) || imageManifest.formatVersion !== 2 || imageManifest.id !== "sandsurf-development" ||
      imageManifest.version !== "3.24.2" || imageManifest.architecture !== architecture ||
      !isRecord(imageManifest.bootBundle) || !isRecord(imageManifest.bootBundle.kernel) ||
      !isRecord(imageManifest.bootBundle.bootstrap) || !isRecord(imageManifest.workload) ||
      !isRecord(imageManifest.workload.rootfs) || !isRecord(imageManifest.workload.stateTemplate) ||
      !isRecord(imageManifest.workload.provenance) || imageManifest.workload.provenance.kind !== "source-built" ||
      !isRecord(imageManifest.workload.provenance.materials)) {
    throw new Error(`${architecture} VM image manifest has an invalid shape`);
  }
  for (const material of ["alpine-minirootfs", "alpine-packages", "sandsurf-ext4-builder"]) {
    if (!validDigest(imageManifest.workload.provenance.materials[material])) {
      throw new Error(`${architecture} VM image is missing ${material} provenance`);
    }
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
  if (!isRecord(imageManifest.platformArtifacts)) throw new Error(`${architecture} platform artifacts are malformed`);
  if (architecture === "x64") {
    const windows = imageManifest.platformArtifacts.windowsX64;
    if (!isRecord(windows)) throw new Error("x64 image has no Windows VM-native artifacts");
    for (const [label, entry] of Object.entries(windows)) {
      if (!isRecord(entry) || typeof entry.path !== "string" || !/^[A-Za-z0-9._-]+$/u.test(entry.path)) {
        throw new Error(`x64 Windows ${label} artifact is malformed`);
      }
      await verifyFile(resolve(imageRoot, entry.path), entry.sha256, `x64 Windows ${label}`);
    }
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
  if (!validDigest(expected)) {
    throw new Error(`${label} has an invalid digest`);
  }
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error(`${label} is not a regular package-owned file`);
  const actual = createHash("sha256").update(await readFile(path)).digest("hex");
  if (actual !== expected) throw new Error(`${label} failed SHA-256 verification`);
}

function validDigest(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
