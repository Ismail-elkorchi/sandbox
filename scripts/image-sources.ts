import { createHash, randomUUID } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { chmod, lstat, mkdir, readFile, rename, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";
import { createGunzip, createGzip } from "node:zlib";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const images = resolve(repository, "packages/sandbox/images");
const sources = resolve(repository, "image-sources");
const maximumImageBytes = 8 * 1024 ** 3;

type ImageEntry = { readonly raw: string; readonly compressed: string; readonly sha256: string };

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function entries(architecture: "x64" | "arm64"): Promise<ImageEntry[]> {
  const directory = `development-${architecture}`;
  const manifest: unknown = JSON.parse(await readFile(resolve(images, directory, "manifest.json"), "utf8"));
  if (!record(manifest) || !record(manifest.bootBundle) || !record(manifest.workload)) {
    throw new Error(`${directory} image manifest is malformed`);
  }
  const artifacts = [manifest.bootBundle.bootstrap, manifest.workload.rootfs, manifest.workload.stateTemplate];
  return artifacts.map((artifact) => {
    if (!record(artifact) || typeof artifact.path !== "string" ||
        !/^[A-Za-z0-9_-][A-Za-z0-9._-]*\.ext4$/u.test(artifact.path) ||
        typeof artifact.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(artifact.sha256)) {
      throw new Error(`${directory} has an invalid ext4 artifact identity`);
    }
    return {
      raw: resolve(images, directory, artifact.path),
      compressed: resolve(sources, directory, `${artifact.path}.gz`),
      sha256: artifact.sha256,
    };
  });
}

async function digestFile(path: string): Promise<string> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maximumImageBytes) {
    throw new Error(`${path} is not a bounded regular image file`);
  }
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

function temporary(path: string): string {
  return `${path}.new-${process.pid}-${randomUUID()}`;
}

export async function packImageSources(architecture: "x64" | "arm64"): Promise<void> {
  for (const entry of await entries(architecture)) {
    if (await digestFile(entry.raw) !== entry.sha256) {
      throw new Error(`${entry.raw} differs from its image manifest`);
    }
    await mkdir(dirname(entry.compressed), { recursive: true });
    const staged = temporary(entry.compressed);
    try {
      await pipeline(createReadStream(entry.raw), createGzip({ level: 9 }),
        createWriteStream(staged, { flags: "wx", mode: 0o644 }));
      await rename(staged, entry.compressed);
    } finally {
      await rm(staged, { force: true });
    }
  }
}

export async function hydrateImageSources(): Promise<void> {
  const index: unknown = JSON.parse(await readFile(resolve(images, "manifest.json"), "utf8"));
  if (!record(index) || !record(index.files)) throw new Error("bundled image index is malformed");
  for (const relative of Object.keys(index.files)) {
    const match = /^development-(x64|arm64)\/manifest\.json$/u.exec(relative);
    if (match === null) throw new Error(`invalid bundled image entry ${relative}`);
    for (const entry of await entries(match[1] as "x64" | "arm64")) {
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
          callback(bytes > maximumImageBytes ? new Error("image source exceeds the ext4 bound") : null, chunk);
        },
      });
      try {
        await pipeline(createReadStream(entry.compressed), createGunzip(), bound,
          createWriteStream(staged, { flags: "wx", mode: 0o600 }));
        if (await digestFile(staged) !== entry.sha256) {
          throw new Error(`${entry.compressed} does not reconstruct its verified ext4 image`);
        }
        await chmod(staged, 0o444);
        await rename(staged, entry.raw);
      } finally {
        await rm(staged, { force: true });
      }
    }
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === "hydrate") await hydrateImageSources();
  else if (process.argv[2] === "pack" && (process.argv[3] === "x64" || process.argv[3] === "arm64")) {
    await packImageSources(process.argv[3]);
  } else throw new Error("use image-sources.ts hydrate or pack <x64|arm64>");
}
