// Source recipes are data. This collector never extracts an archive, invokes
// abuild, or evaluates APKBUILD on the host. The signed installed metadata
// selects an exact aPorts commit; upstream bytes must match its SHA-512 list.
import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { chmod, copyFile, link, lstat, mkdir, open, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { get } from "node:https";
import { relative, resolve } from "node:path";

const CHUNK = 32 * 1024 * 1024;
const MAX_SOURCE = 384 * 1024 * 1024;
const MAX_TOTAL = 2 * 1024 ** 3;
const DIGEST = /^[a-f0-9]{64}$/u;
const NAME = /^[a-z0-9][a-z0-9+_.-]{0,127}$/u;
const FILE = /^[A-Za-z0-9_][A-Za-z0-9_.+@\-]{0,191}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;

export interface SourceChunk { sha256: string; bytes: number }
export interface SourceMaterial { sha256: string; sha512: string; bytes: number; chunks: SourceChunk[] }
export interface SourceOrigin {
  origin: string; buildCommit: string; repository: "main" | "community";
  recipes: Record<string, SourceMaterial>;
  sources: Record<string, SourceMaterial>;
}
export interface SourceInventory { formatVersion: 1; origins: SourceOrigin[] }
export interface PackageOrigin { origin: string; buildCommit: string }
export type SourceTransport = (url: string, maximum: number) => Promise<AsyncIterable<Uint8Array> | undefined>;

function fail(message: string): never { throw new Error(`Alpine corresponding source: ${message}`); }
function hash(bytes: Uint8Array): string { return createHash("sha256").update(bytes).digest("hex"); }
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
export function alpinePackageOrigins(value: unknown): PackageOrigin[] {
  if (!record(value) || value.kind !== "alpine" || !Array.isArray(value.packages)) fail("missing installed package inventory");
  const packages = value.packages.map((item: unknown) => {
    if (!record(item) || typeof item.origin !== "string" || typeof item.buildCommit !== "string") fail("missing installed source origin");
    return { origin: item.origin, buildCommit: item.buildCommit };
  });
  origins(packages);
  return packages;
}
function origins(packages: readonly PackageOrigin[]): Map<string, PackageOrigin> {
  if (packages.length === 0 || packages.length > 512) fail("invalid installed package count");
  const values = new Map<string, PackageOrigin>();
  for (const value of packages) {
    if (!NAME.test(value.origin) || !COMMIT.test(value.buildCommit)) fail("invalid signed origin/commit");
    values.set(`${value.origin}:${value.buildCommit}`, { origin: value.origin, buildCommit: value.buildCommit });
  }
  return new Map([...values].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
}

/** This distribution profile accepts one literal checksum declaration, not a
 * partial shell evaluator. Dynamic/ambiguous declarations fail. Empty-source
 * metapackages retain their complete aPorts recipe directory instead. */
export function recipeChecksums(bytes: Uint8Array): Map<string, string> {
  if (bytes.length === 0 || bytes.length > 256 * 1024) fail("recipe exceeds bound");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (text.includes("\0") || text.includes("\r")) fail("invalid recipe encoding");
  const assignments = [...text.matchAll(/^\s*(?:export\s+)?sha512sums\s*\+?=/gmu)];
  if (assignments.length === 0) {
    const sources = [...text.matchAll(/^\s*(?:export\s+)?source\s*\+?=(.*)$/gmu)];
    if (sources.some((value) => !/^(?:""|'')\s*$/u.test(value[1]!))) fail("source recipe lacks literal SHA-512 checksums");
    return new Map();
  }
  const match = /^sha512sums="([^"$`\\]*)"\s*$/mu.exec(text);
  if (assignments.length !== 1 || match === null) fail("dynamic or ambiguous SHA-512 declaration");
  const values = new Map<string, string>();
  for (const line of match[1]!.split("\n").filter((line) => line.trim() !== "")) {
    const entry = /^([a-f0-9]{128})  ([^\s]+)$/u.exec(line);
    if (entry === null || !FILE.test(entry[2]!) || values.has(entry[2]!) || values.size >= 256) fail(`malformed checksum inventory: ${JSON.stringify(line.slice(0, 256))}`);
    values.set(entry[2]!, entry[1]!);
  }
  return values;
}

/** Strict TLS origins and finite streams. A 404 is repository/file discovery,
 * not permission to change mirrors, execute a recipe, or omit its source. */
export const sourceTransport: SourceTransport = async (url, maximum) => {
  const address = new URL(url);
  if (!['https://raw.githubusercontent.com', 'https://api.github.com', 'https://distfiles.alpinelinux.org'].includes(address.origin) ||
      address.username || address.password || address.hash || !Number.isSafeInteger(maximum) || maximum <= 0 || maximum > MAX_SOURCE) fail("invalid source transport");
  return new Promise((resolveResponse, rejectResponse) => {
    const timer = setTimeout(() => request.destroy(new Error("source download deadline exceeded")), 300_000);
    const request = get(url, { headers: { "User-Agent": "sandsurf-source-collector", Accept: "application/vnd.github+json" } }, (response) => {
      if (response.statusCode === 404) { clearTimeout(timer); response.destroy(); resolveResponse(undefined); return; }
      const length = response.headers["content-length"];
      if (response.statusCode !== 200 || (length !== undefined && (!/^[0-9]+$/u.test(length) || Number(length) > maximum))) {
        clearTimeout(timer); response.destroy(); rejectResponse(new Error(`source download rejected status/length (${response.statusCode}): ${url}`)); return;
      }
      response.once("close", () => clearTimeout(timer));
      resolveResponse((async function* () {
        let bytes = 0;
        try {
          for await (const chunk of response) {
            bytes += chunk.length;
            if (bytes > maximum) fail("source stream exceeds bound");
            yield chunk as Buffer;
          }
          if (bytes === 0 || length !== undefined && bytes !== Number(length)) fail("source stream is empty or truncated");
        } finally { clearTimeout(timer); response.destroy(); }
      })());
    });
    request.setTimeout(30_000, () => request.destroy(new Error("source download stalled")));
    request.on("error", (error) => { clearTimeout(timer); rejectResponse(error); });
  });
};

async function bounded(stream: AsyncIterable<Uint8Array>, maximum: number): Promise<Buffer> {
  let total = 0; const parts: Buffer[] = [];
  for await (const bytes of stream) {
    total += bytes.length; if (total > maximum) fail("metadata exceeds bound");
    parts.push(Buffer.from(bytes));
  }
  if (total === 0) fail("empty metadata");
  return Buffer.concat(parts, total);
}
async function readDocument(path: string): Promise<Buffer> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0 || metadata.size > 4 * 1024 * 1024) fail("invalid source inventory file");
  const bytes = await readFile(path);
  if (bytes.length !== metadata.size) fail("source inventory changed length");
  return bytes;
}
async function storeMaterial(root: string, stream: AsyncIterable<Uint8Array>, maximum: number): Promise<SourceMaterial> {
  const sha256 = createHash("sha256"), sha512 = createHash("sha512");
  const chunks: SourceChunk[] = [];
  let bytes = 0, partBytes = 0;
  const objects = resolve(root, "objects"); await mkdir(objects, { recursive: true });
  let name = resolve(objects, `.pending-${randomUUID()}`);
  let file = await open(name, "wx", 0o600);
  let partHash = createHash("sha256");
  async function finish(): Promise<void> {
    if (partBytes === 0) return;
    await file.sync(); await file.close();
    const digest = partHash.digest("hex"); const target = resolve(objects, digest);
    await chmod(name, 0o444);
    try { await link(name, target); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      await verifyChunk(root, { sha256: digest, bytes: partBytes });
    }
    await rm(name); chunks.push({ sha256: digest, bytes: partBytes });
  }
  try {
    for await (const value of stream) {
      bytes += value.length;
      if (bytes > maximum || bytes > MAX_SOURCE) fail("material exceeds bound");
      sha256.update(value); sha512.update(value);
      for (let offset = 0; offset < value.length;) {
        if (partBytes === CHUNK) {
          await finish(); partBytes = 0; partHash = createHash("sha256");
          name = resolve(objects, `.pending-${randomUUID()}`); file = await open(name, "wx", 0o600);
        }
        const segment = value.subarray(offset, offset + Math.min(CHUNK - partBytes, value.length - offset));
        await file.writeFile(segment); partHash.update(segment); partBytes += segment.length; offset += segment.length;
      }
    }
    if (bytes === 0) fail("empty source material");
    await finish();
    return { sha256: sha256.digest("hex"), sha512: sha512.digest("hex"), bytes, chunks };
  } finally { await file.close().catch(() => {}); await rm(name, { force: true }); }
}
async function verifyChunk(root: string, chunk: SourceChunk): Promise<string> {
  if (!DIGEST.test(chunk.sha256) || !Number.isSafeInteger(chunk.bytes) || chunk.bytes <= 0 || chunk.bytes > CHUNK) fail("invalid source chunk");
  const path = resolve(root, "objects", chunk.sha256), metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size !== chunk.bytes) fail("missing or changed source bytes");
  const hash_ = createHash("sha256");
  for await (const value of createReadStream(path, { highWaterMark: 65536 })) hash_.update(value);
  if (hash_.digest("hex") !== chunk.sha256) fail("changed source chunk digest");
  return path;
}

export async function collectAlpineSources(root: string, packages: readonly PackageOrigin[], transport = sourceTransport): Promise<string> {
  root = resolve(root);
  await mkdir(root, { recursive: true });
  const inventory: SourceInventory = { formatVersion: 1, origins: [] };
  let total = 0;
  for (const value of origins(packages).values()) {
    let repository: SourceOrigin["repository"] | undefined, listing: unknown;
    for (const candidate of ["main", "community"] as const) {
      const stream = await transport(`https://api.github.com/repos/alpinelinux/aports/contents/${candidate}/${value.origin}?ref=${value.buildCommit}`, 1024 * 1024);
      if (stream !== undefined) { listing = JSON.parse((await bounded(stream, 1024 * 1024)).toString("utf8")); repository = candidate; break; }
    }
    if (repository === undefined || !Array.isArray(listing) || listing.length === 0 || listing.length > 256) fail("exact aPorts recipe directory is unavailable");
    const recipes: Record<string, SourceMaterial> = {};
    let checksums: Map<string, string> | undefined;
    for (const item of listing as unknown[]) {
      if (!record(item) || item.type !== "file" || typeof item.name !== "string" || !FILE.test(item.name) ||
          item.path !== `${repository}/${value.origin}/${item.name}` || typeof item.sha !== "string" || !COMMIT.test(item.sha) ||
          !Number.isSafeInteger(item.size) || (item.size as number) <= 0 || (item.size as number) > 2 * 1024 * 1024 || Object.hasOwn(recipes, item.name)) fail("invalid aPorts file identity");
      const stream = await transport(`https://raw.githubusercontent.com/alpinelinux/aports/${value.buildCommit}/${item.path}`, 2 * 1024 * 1024);
      if (stream === undefined) fail("missing aPorts file");
      const bytes = await bounded(stream, 2 * 1024 * 1024);
      if (bytes.length !== item.size || createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex") !== item.sha) fail("aPorts Git blob identity changed");
      if (item.name === "APKBUILD") {
        try { checksums = recipeChecksums(bytes); }
        catch (error) { throw new Error(`invalid source recipe ${value.origin}@${value.buildCommit}`, { cause: error }); }
      }
      recipes[item.name] = await storeMaterial(root, (async function* () { yield bytes; })(), 2 * 1024 * 1024);
      total += bytes.length; if (total > MAX_TOTAL) fail("source closure exceeds bound");
    }
    if (checksums === undefined) fail("aPorts directory has no APKBUILD");
    const sources: Record<string, SourceMaterial> = {};
    for (const [name, checksum] of checksums) {
      const local = recipes[name];
      if (local !== undefined) {
        if (local.sha512 !== checksum) fail("local recipe material differs from SHA-512 declaration");
        sources[name] = local; continue;
      }
      const stream = await transport(`https://distfiles.alpinelinux.org/distfiles/v3.24/${name}`, MAX_SOURCE);
      if (stream === undefined) fail(`missing corresponding archive ${value.origin}/${name}`);
      const material = await storeMaterial(root, stream, MAX_SOURCE);
      if (material.sha512 !== checksum) fail(`corresponding archive digest mismatch: ${value.origin}/${name}`);
      total += material.bytes; if (total > MAX_TOTAL) fail("source closure exceeds bound");
      sources[name] = material;
    }
    inventory.origins.push({ ...value, repository, recipes: Object.fromEntries(Object.entries(recipes).sort()), sources: Object.fromEntries(Object.entries(sources).sort()) });
  }
  const bytes = Buffer.from(`${JSON.stringify(inventory, null, 2)}\n`), digest = hash(bytes);
  const path = resolve(root, `${digest}.json`);
  try { await writeFile(path, bytes, { flag: "wx", mode: 0o444 }); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST" || !bytes.equals(await readDocument(path))) throw error;
  }
  await verifyAlpineSources(root, digest, packages);
  return digest;
}

/** The inventory is an immutable declaration; only verification of all actual
 * chunks and reassembled material digests establishes source-byte coverage. */
export async function verifyAlpineSources(root: string, digest: string, packages: readonly PackageOrigin[]): Promise<string[]> {
  root = resolve(root);
  for (const path of [root, resolve(root, "objects")]) {
    const metadata = await lstat(path);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail("source namespace is aliased");
  }
  if (!DIGEST.test(digest)) fail("invalid source inventory digest");
  const path = resolve(root, `${digest}.json`), bytes = await readDocument(path);
  if (hash(bytes) !== digest) fail("changed source inventory");
  const value: unknown = JSON.parse(bytes.toString("utf8"));
  const expected = origins(packages), files = new Set([path]);
  if (!record(value) || value.formatVersion !== 1 || !Array.isArray(value.origins) || value.origins.length !== expected.size) fail("source origin coverage differs from installed OS");
  let total = 0;
  for (const item of value.origins as unknown[]) {
    if (!record(item) || typeof item.origin !== "string" || typeof item.buildCommit !== "string" ||
        !expected.delete(`${item.origin}:${item.buildCommit}`) || !["main", "community"].includes(item.repository as string) ||
        !record(item.recipes) || !record(item.sources) || !Object.hasOwn(item.recipes, "APKBUILD") ||
        Object.keys(item.recipes).length > 256 || Object.keys(item.sources).length > 256) fail("invalid corresponding source origin");
    const materials = new Map<string, SourceMaterial>();
    for (const [name, input] of [...Object.entries(item.recipes), ...Object.entries(item.sources)]) {
      if (!FILE.test(name) || !record(input) || !DIGEST.test(input.sha256 as string) ||
          typeof input.sha512 !== "string" || !/^[a-f0-9]{128}$/u.test(input.sha512) ||
          !Number.isSafeInteger(input.bytes) || (input.bytes as number) <= 0 || (input.bytes as number) > MAX_SOURCE ||
          !Array.isArray(input.chunks) || input.chunks.length === 0 || input.chunks.length > 12) fail("invalid source material");
      const material = input as unknown as SourceMaterial;
      if (materials.has(name)) { if (JSON.stringify(materials.get(name)) !== JSON.stringify(material)) fail("conflicting local source identity"); continue; }
      materials.set(name, material);
      const sha256 = createHash("sha256"), sha512 = createHash("sha512"); let length = 0;
      for (const chunk of material.chunks) {
        if (!record(chunk)) fail("invalid chunk record");
        const part = await verifyChunk(root, chunk);
        files.add(part);
        for await (const bytes of createReadStream(part, { highWaterMark: 65536 })) { length += bytes.length; sha256.update(bytes); sha512.update(bytes); }
        if (length > material.bytes) fail("source reassembly exceeds declaration");
      }
      if (length !== material.bytes || sha256.digest("hex") !== material.sha256 || sha512.digest("hex") !== material.sha512) fail("source reassembly identity mismatch");
      total += length; if (total > MAX_TOTAL) fail("source closure exceeds bound");
    }
    const recipe = materials.get("APKBUILD")!;
    if (recipe.bytes > 256 * 1024) fail("recipe exceeds bound");
    const chunks = await Promise.all(recipe.chunks.map((chunk) => readFile(resolve(root, "objects", chunk.sha256))));
    const checksums = recipeChecksums(Buffer.concat(chunks));
    if (Object.keys(item.sources).length !== checksums.size) fail("checksum source coverage is incomplete");
    for (const [name, checksum] of checksums) if (!record(item.sources[name]) || item.sources[name].sha512 !== checksum) fail("recipe/source binding mismatch");
  }
  if (expected.size !== 0) fail("missing source origin");
  return [...files].sort();
}

/** Replace only a generated source bundle after its whole byte closure has
 * verified. Existing unknown names or aliases are never erased by a build. */
export async function publishAlpineSources(source: string, destination: string, digest: string, packages: readonly PackageOrigin[]): Promise<void> {
  source = resolve(source); destination = resolve(destination);
  const files = await verifyAlpineSources(source, digest, packages);
  async function owned(root: string): Promise<void> {
    const metadata = await lstat(root);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail("generated source namespace is aliased");
    const entries = await readdir(root);
    const inventory = entries.filter((name) => /^[a-f0-9]{64}\.json$/u.test(name));
    if (entries.length !== 2 || !entries.includes("objects") || inventory.length !== 1) fail("generated source namespace has unowned files");
    const bytes = await readDocument(resolve(root, inventory[0]!));
    const value: unknown = JSON.parse(bytes.toString("utf8"));
    if (!record(value) || !Array.isArray(value.origins)) fail("invalid previous source ownership");
    const origins_ = value.origins.map((item: unknown) => {
      if (!record(item) || typeof item.origin !== "string" || typeof item.buildCommit !== "string") fail("invalid previous source origin");
      return { origin: item.origin, buildCommit: item.buildCommit };
    });
    const expected = new Set(await verifyAlpineSources(root, inventory[0]!.slice(0, 64), origins_));
    const objects = await readdir(resolve(root, "objects"));
    if (objects.length > 4096 || objects.length + 1 !== expected.size || objects.some((name) => !expected.has(resolve(root, "objects", name)))) fail("generated source namespace has unowned objects");
  }
  let exists = false;
  try { await lstat(destination); exists = true; }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  if (exists) await owned(destination);
  const stage = `${destination}.new-${randomUUID()}`, previous = `${destination}.previous-${randomUUID()}`;
  await mkdir(stage); await mkdir(resolve(stage, "objects"));
  let moved = false, published = false;
  try {
    for (const file of files) {
      const output = resolve(stage, relative(source, file));
      await copyFile(file, output); await chmod(output, 0o444);
    }
    await verifyAlpineSources(stage, digest, packages);
    if (exists) { await rename(destination, previous); moved = true; }
    try { await rename(stage, destination); published = true; }
    catch (error) { if (moved) { await rename(previous, destination); moved = false; } throw error; }
  } finally {
    await rm(stage, { recursive: true, force: true });
    if (moved && published) await rm(previous, { recursive: true });
  }
}
