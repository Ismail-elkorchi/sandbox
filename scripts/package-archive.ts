import { lstat, mkdir, mkdtemp, readFile, rename, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { createWriteStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import type { Readable } from "node:stream";

/** The image/native manifests define the distribution closure. Reject extra
 * artifacts, not just a growing blacklist of names from retired backends. */
export function assertPayloadClosure(paths: readonly string[], prefix: string, expected: readonly string[]): void {
  if (!prefix.startsWith("package/") || !prefix.endsWith("/") || expected.length > 4096 ||
      expected.some((path) => !path.startsWith(prefix) || path.endsWith("/")) ||
      new Set(expected).size !== expected.length) throw new Error("invalid package payload inventory");
  const missing = new Set(expected);
  const admitted = new Set(expected);
  for (const path of paths) {
    if (!path.startsWith(prefix) || path.endsWith("/")) continue;
    if (!admitted.has(path)) throw new Error(`undeclared package payload ${path}`);
    if (!missing.delete(path)) throw new Error(`duplicate package payload ${path}`);
  }
  if (missing.size !== 0) throw new Error(`missing package payload ${missing.values().next().value}`);
}

/** Use npm's package selection and tar writer, without libnpmpack's whole-archive Buffer. */
export async function packageArchive(directory: string, destination: string, npmCli: string): Promise<string> {
  const source = resolve(directory);
  const metadata = await lstat(resolve(source, "package.json"));
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 64 * 1024) {
    throw new Error("package manifest must be a bounded regular file");
  }
  const manifest: unknown = JSON.parse(await readFile(resolve(source, "package.json"), "utf8"));
  if (typeof manifest !== "object" || manifest === null || !("name" in manifest) ||
      typeof manifest.name !== "string" || !/^[a-z0-9][a-z0-9-]*$/u.test(manifest.name) ||
      !("version" in manifest) || typeof manifest.version !== "string" ||
      !/^[0-9]+\.[0-9]+\.[0-9]+$/u.test(manifest.version)) {
    throw new Error("package identity is invalid");
  }
  const scripts = "scripts" in manifest ? manifest.scripts : undefined;
  if (typeof scripts === "object" && scripts !== null &&
      ["prepare", "prepack", "postpack"].some((name) => name in scripts)) {
    throw new Error("package lifecycle hooks are forbidden; build artifacts explicitly before packing");
  }
  // Use the selected npm installation's package inventory and canonical tar
  // metadata. Own the streaming budget: pacote's default tar writer permits
  // four concurrent entries with 16 MiB reads each, even for a small JS heap.
  const npmRequire = createRequire(resolve(npmCli));
  const pacote = npmRequire("pacote") as {
    DirFetcher: { tarCreateOptions(manifest: Record<string, unknown>): Record<string, unknown> };
  };
  const Arborist = npmRequire("@npmcli/arborist") as new (options: { path: string }) => {
    loadActual(): Promise<unknown>;
  };
  const packlist = npmRequire("npm-packlist") as (tree: unknown, options: { path: string }) => Promise<string[]>;
  const tar = npmRequire("tar") as { c(options: Record<string, unknown>, files: readonly string[]): Readable };
  const tree = await new Arborist({ path: source }).loadActual();
  const files = await packlist(tree, { path: source });
  await mkdir(destination, { recursive: true });
  const stage = await mkdtemp(resolve(destination, ".package-"));
  const filename = `${manifest.name}-${manifest.version}.tgz`;
  const output = resolve(destination, filename);
  try {
    await pipeline(tar.c({
      ...pacote.DirFetcher.tarCreateOptions({ ...manifest, _resolved: source }),
      maxReadSize: 64 * 1024,
      jobs: 1,
    }, files), createWriteStream(resolve(stage, filename), { flags: "wx", highWaterMark: 64 * 1024 }));
    await rename(resolve(stage, filename), output);
    return output;
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}
