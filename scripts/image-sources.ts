import { createHash, randomUUID } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { chmod, copyFile, link, lstat, mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";
import { createGunzip, createGzip } from "node:zlib";
import { sha256File } from "../packages/sandsurf/src/file-integrity.ts";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const images = resolve(repository, "packages/sandsurf/images");
const sources = resolve(repository, "image-sources");
const maximumImageBytes = 8 * 1024 ** 3;

type ImageEntry = { readonly raw: string; readonly compressed: string; readonly sha256: string };
type ImageRoots = { readonly images: string; readonly sources: string };
const defaultRoots: ImageRoots = { images, sources };

export async function writeImageIndex(root = images, required: readonly string[] = []): Promise<void> {
  const missing = new Set(required);
  for (const architecture of missing) if (architecture !== "x64" && architecture !== "arm64") {
    throw new Error(`unsupported required guest architecture ${architecture}`);
  }
  const files: Record<string, string> = {};
  for (const directory of (await readdir(root, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const match = /^development-(x64|arm64)$/u.exec(directory.name);
    if (!directory.isDirectory() || match === null) continue;
    const relative = `${directory.name}/manifest.json`;
    const path = resolve(root, relative);
    let metadata;
    try { metadata = await lstat(path); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") continue; throw error; }
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 1024 ** 2) throw new Error(`${relative} is not a bounded regular manifest`);
    const bytes = await readFile(path);
    const manifest: unknown = JSON.parse(bytes.toString("utf8"));
    if (!record(manifest) || manifest.formatVersion !== 1 || manifest.architecture !== match[1]
      || !record(manifest.system) || !record(manifest.system.rootfs) || !record(manifest.bootBundle)) {
      throw new Error(`${relative} is not a current machine image`);
    }
    files[relative] = createHash("sha256").update(bytes).digest("hex");
    missing.delete(match[1]!);
  }
  if (missing.size !== 0) throw new Error(`required guest images are absent: ${[...missing].join(", ")}`);
  if (Object.keys(files).length === 0) throw new Error("no machine images were found");
  await writeFile(resolve(root, "manifest.json"), `${JSON.stringify({ formatVersion: 1, buildId: "sandsurf-images-1.0.0", files }, null, 2)}\n`, { mode: 0o644 });
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function entries(architecture: "x64" | "arm64", roots: ImageRoots): Promise<ImageEntry[]> {
  const directory = `development-${architecture}`;
  const manifest: unknown = JSON.parse(await readFile(resolve(roots.images, directory, "manifest.json"), "utf8"));
  if (!record(manifest) || !record(manifest.bootBundle) || !record(manifest.system)) {
    throw new Error(`${directory} image manifest is malformed`);
  }
  if (manifest.formatVersion !== 1) throw new Error(`${directory} is not a machine image`);
  if (Object.keys(manifest).some((key) => !["formatVersion", "id", "version", "architecture", "bootBundle", "system", "signature"].includes(key))) {
    throw new Error(`${directory} has unknown machine image fields`);
  }
  const artifact = manifest.system.rootfs;
  if (!record(artifact) || typeof artifact.path !== "string" ||
      !/^[A-Za-z0-9_-][A-Za-z0-9._-]*\.ext4$/u.test(artifact.path) ||
      typeof artifact.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(artifact.sha256)) {
    throw new Error(`${directory} has an invalid ext4 artifact identity`);
  }
  return [{
    raw: resolve(roots.images, directory, artifact.path),
    compressed: resolve(roots.sources, directory, `${artifact.path}.gz`),
    sha256: artifact.sha256,
  }];
}

async function digestFile(path: string): Promise<string> {
  return sha256File(path, maximumImageBytes);
}

function temporary(path: string): string {
  return `${path}.new-${process.pid}-${randomUUID()}`;
}

export async function packImageSources(architecture: "x64" | "arm64", roots: ImageRoots = defaultRoots): Promise<void> {
  for (const entry of await entries(architecture, roots)) {
    if (await digestFile(entry.raw) !== entry.sha256) {
      throw new Error(`${entry.raw} differs from its image manifest`);
    }
    await mkdir(dirname(entry.compressed), { recursive: true });
    const staged = temporary(entry.compressed);
    try {
      await pipeline(createReadStream(entry.raw), createGzip({ level: 9 }),
        createWriteStream(staged, { flags: "wx", mode: 0o644 }));
      await rename(staged, entry.compressed);
      await publishBuiltTransport(entry);
    } finally {
      await rm(staged, { force: true });
    }
  }
}

export async function hydrateImageSources(roots: ImageRoots = defaultRoots): Promise<void> {
  const index: unknown = JSON.parse(await readFile(resolve(roots.images, "manifest.json"), "utf8"));
  if (!record(index) || index.formatVersion !== 1 || index.buildId !== "sandsurf-images-1.0.0" ||
      !record(index.files)) throw new Error("bundled image index is malformed");
  for (const [relative, digest] of Object.entries(index.files)) {
    const match = /^development-(x64|arm64)\/manifest\.json$/u.exec(relative);
    if (match === null) throw new Error(`invalid bundled image entry ${relative}`);
    if (typeof digest !== "string" || !/^[a-f0-9]{64}$/u.test(digest) ||
        await digestFile(resolve(roots.images, relative)) !== digest) {
      throw new Error(`${relative} differs from the image index`);
    }
    for (const entry of await entries(match[1] as "x64" | "arm64", roots)) {
      await publishDistributionSource(entry);
      try {
        if (await digestFile(entry.raw) !== entry.sha256) {
          throw new Error(`${entry.raw} differs from its image manifest`);
        }
        continue;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      const compressed = await lstat(entry.compressed);
      if (!compressed.isFile() || compressed.isSymbolicLink()) {
        throw new Error(`${entry.compressed} is not a regular image source`);
      }
      const staged = temporary(entry.raw);
      let bytes = 0;
      const bound = new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          bytes += chunk.length;
          callback(bytes > maximumImageBytes ? new Error("image source exceeds the disk bound") : null, chunk);
        },
      });
      try {
        await pipeline(createReadStream(entry.compressed), createGunzip(), bound,
          createWriteStream(staged, { flags: "wx", mode: 0o600 }));
        if (await digestFile(staged) !== entry.sha256) {
          throw new Error(`${entry.compressed} does not reconstruct its verified disk image`);
        }
        await chmod(staged, 0o444);
        await rename(staged, entry.raw);
      } finally {
        await rm(staged, { force: true });
      }
    }
  }
}

/** Explicit image production replaces a generated build output. Hydration
 * instead consumes an existing identity and must never replace its bytes.
 * Neither operation mutates the host's content-addressed image store.
 */
async function publishBuiltTransport(entry: ImageEntry): Promise<void> {
  await verifyDiskTransport(entry.compressed, entry.sha256);
  const target = `${entry.raw}.gz`;
  const staged = temporary(target);
  const previous = temporary(target);
  let moved = false;
  let published = false;
  try {
    await copyFile(entry.compressed, staged);
    await verifyDiskTransport(staged, entry.sha256);
    await chmod(staged, 0o444);
    try {
      await digestFile(target); // Reject links, oversized or changing artifacts.
      await rename(target, previous);
      moved = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    try {
      await rename(staged, target);
      published = true;
    } catch (error) {
      if (moved) { await rename(previous, target); moved = false; }
      throw error;
    }
  } finally {
    await rm(staged, { force: true });
    if (published && moved) await rm(previous, { force: true });
  }
}

async function publishDistributionSource(entry: ImageEntry): Promise<void> {
  const compressedDigest = await digestFile(entry.compressed);
  await verifyDiskTransport(entry.compressed, entry.sha256);
  const target = `${entry.raw}.gz`;
  try {
    await verifyDiskTransport(target, entry.sha256);
    return;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const staged = temporary(target);
  try {
    await copyFile(entry.compressed, staged);
    if (await digestFile(staged) !== compressedDigest) throw new Error("distribution source changed during publication");
    await chmod(staged, 0o444);
    try {
      // Publish without replacing a competing or readonly immutable artifact.
      await link(staged, target);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      await verifyDiskTransport(target, entry.sha256);
    }
  } finally { await rm(staged, { force: true }); }
}

export async function verifyDiskTransport(path: string, expectedDigest: string): Promise<void> {
  if (!/^[a-f0-9]{64}$/u.test(expectedDigest)) throw new Error("invalid decoded disk digest");
  await digestFile(path);
  const hash = createHash("sha256");
  let bytes = 0;
  await pipeline(createReadStream(path), createGunzip(), new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      bytes += chunk.length;
      if (bytes > maximumImageBytes) callback(new Error("distribution disk exceeds capacity bound"));
      else { hash.update(chunk); callback(); }
    },
  }));
  if (hash.digest("hex") !== expectedDigest) throw new Error(`${path} does not reconstruct its verified disk image`);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === "hydrate") await hydrateImageSources();
  else if (process.argv[2] === "pack" && (process.argv[3] === "x64" || process.argv[3] === "arm64")) {
    await packImageSources(process.argv[3]);
  } else throw new Error("use image-sources.ts hydrate or pack <x64|arm64>");
}
