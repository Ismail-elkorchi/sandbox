import { lstat, readFile, readdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256File } from "../packages/sandsurf/src/file-integrity.ts";
import { verifyDiskTransport } from "./image-sources.ts";
import { verifyQemuRuntime } from "./qemu-runtime.ts";
import { dependencySourceFiles, verifyDependencySources } from "./qemu-dependencies.ts";
import { imageComponents } from "./image-supply-chain.ts";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
await verifyManifest(resolve(repository, "native/manifest.json"), resolve(repository, "native"));
await verifyManifest(
  resolve(repository, "packages/sandsurf/native/manifest.json"),
  resolve(repository, "packages/sandsurf/native"),
);
const imagesRoot = resolve(repository, "packages/sandsurf/images");
const imageIndexPath = resolve(imagesRoot, "manifest.json");
await verifyManifest(imageIndexPath, imagesRoot);
await imageComponents(imagesRoot);
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
  if (!isRecord(imageManifest) || imageManifest.formatVersion !== 1 || imageManifest.id !== "sandsurf-development" ||
      imageManifest.version !== "3.24.2" || imageManifest.architecture !== architecture ||
      !isRecord(imageManifest.bootBundle) || !isRecord(imageManifest.bootBundle.kernel) ||
      !isRecord(imageManifest.system) ||
      !isRecord(imageManifest.system.rootfs) ||
      !isRecord(imageManifest.system.provenance) || imageManifest.system.provenance.kind !== "assembled" ||
      !isRecord(imageManifest.system.provenance.materials)) {
    throw new Error(`${architecture} VM image manifest has an invalid shape`);
  }
  for (const material of ["alpine-minirootfs", "alpine-offline-packages", "alpine-package-lock", "alpine-installed-database", "alpine-corresponding-sources", "sandsurf-system-recipe", "sandsurf-appliance-recipe", "sandsurf-management"]) {
    if (!validDigest(imageManifest.system.provenance.materials[material])) {
      throw new Error(`${architecture} VM image is missing ${material} provenance`);
    }
  }
  for (const [label, entry] of [
    ["VM kernel", imageManifest.bootBundle.kernel],
    ["VM system seed", imageManifest.system.rootfs],
  ] as const) {
    if (typeof entry.path !== "string" || !/^[A-Za-z0-9._-]+$/u.test(entry.path)) {
      throw new Error(`${architecture} ${label} path is invalid`);
    }
    await verifyFile(resolve(imageRoot, entry.path), entry.sha256, `${architecture} ${label}`);
    if (label === "VM system seed") await verifyDiskTransport(resolve(imageRoot, `${entry.path}.gz`), entry.sha256 as string);
  }
  const initramfs = imageManifest.bootBundle.initramfs;
  if (!isRecord(initramfs) || typeof initramfs.path !== "string" || !/^[A-Za-z0-9._-]+$/u.test(initramfs.path)) {
    throw new Error(`${architecture} VM initramfs is malformed`);
  }
  await verifyFile(resolve(imageRoot, initramfs.path), initramfs.sha256, `${architecture} VM initramfs`);

}
if (required.size !== 0) throw new Error(`required VM images are absent: ${[...required].join(", ")}`);

async function verifyManifest(manifestPath: string, base: string): Promise<void> {
  const manifest: unknown = JSON.parse(await readFile(manifestPath, "utf8"));
  if (!isRecord(manifest) || !isRecord(manifest.files)) throw new Error(`${manifestPath} has an invalid shape`);
  for (const entry of await readdir(base, { withFileTypes: true })) {
    if (entry.isDirectory() && /^(?:macos-(?:x64|arm64)|windows-x64)$/u.test(entry.name)) {
      const inputs = await verifyQemuRuntime(resolve(base, entry.name), entry.name);
      for (const path of dependencySourceFiles(await verifyDependencySources(resolve(base, entry.name), inputs))) {
        if (manifest.files[`${entry.name}/${path}`] === undefined) throw new Error("native dependency source is not in the package index");
      }
      for (const [path, digest] of Object.entries(inputs)) {
        if (manifest.files[`${entry.name}/${path}`] !== digest) throw new Error("QEMU runtime and native package identities differ");
      }
    }
  }
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
  const actual = await sha256File(path, 8 * 1024 ** 3);
  if (actual !== expected) throw new Error(`${label} failed SHA-256 verification`);
}

function validDigest(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
