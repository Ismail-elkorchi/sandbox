import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { sha256File } from "../packages/sandsurf/src/file-integrity.ts";

/** An executable can manage imported images without bundling a default OS.
 * Missing architecture entries mean no default; declared entries must verify.
 * Release assembly separately requires the complete image architecture set.
 */
export async function bundledImageManifestDigest(images: string, architecture: "x64" | "arm64"): Promise<string | undefined> {
  const index: unknown = JSON.parse(await readFile(resolve(images, "manifest.json"), "utf8"));
  if (!record(index) || index.formatVersion !== 1 || !record(index.files)) throw new Error("bundled image index is malformed");
  const relative = `development-${architecture}/manifest.json`;
  if (!Object.hasOwn(index.files, relative)) return undefined;
  const expected = index.files[relative];
  if (typeof expected !== "string" || !/^[a-f0-9]{64}$/u.test(expected)) throw new Error("bundled image identity is malformed");
  const actual = await sha256File(resolve(images, relative), 1024 * 1024);
  if (actual !== expected) throw new Error("bundled image manifest differs from its image index");
  return actual;
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
