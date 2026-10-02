import { copyFile, lstat, mkdir, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import { relative, resolve } from "node:path";
import { runtimeDigest } from "./qemu-runtime.ts";

export interface LibraryInput { path: string; sha256: string }
export interface DependencyComponent {
  manager: "homebrew" | "msys2";
  name: string;
  version: string;
  license: string;
  binaries: Record<string, { inputSha256: string; sha256: string }>;
  materials: Record<string, string>;
}
export interface DependencyManifest { formatVersion: 1; components: DependencyComponent[] }
export type BuildRunner = (command: string, arguments_: readonly string[], cwd: string, capture?: boolean,
  environment?: Readonly<Record<string, string>>) => Promise<string>;

const maximumBytes = 512 * 1024 ** 2;
const safeName = /^[A-Za-z0-9_.+-]+$/u;
const sha256 = /^[a-f0-9]{64}$/u;

/** Preserve the source corresponding to the actual installed library, not the
 * currently published version of its formula/package. Package-manager checksum
 * or signature verification happens before copying source into the artifact.
 * Source and recipe bytes are shipped, not represented by download links. */
export async function collectDependencySources(destination: string, libraries: ReadonlyMap<string, LibraryInput>,
  scratch: string, run: BuildRunner): Promise<void> {
  if (!['darwin', 'win32'].includes(process.platform)) throw new Error("native library source collection requires its build host");
  const components = new Map<string, DependencyComponent>();
  const cellar = process.platform === "darwin" ? await realpath((await run("brew", ["--cellar"], scratch, true)).trim()) : undefined;
  for (const [binary, input] of libraries) {
    if (await runtimeDigest(input.path) !== input.sha256) throw new Error("installed QEMU dependency changed during build");
    const origin = process.platform === "darwin"
      ? await homebrewOrigin(input.path, cellar!, scratch, run)
      : await msysOrigin(input.path, scratch, run);
    const identity = `${origin.manager}:${origin.name}:${origin.version}`;
    let component = components.get(identity);
    if (component === undefined) {
      if (components.size >= 32) throw new Error("native dependency package count exceeds its bound");
      if ([...components.values()].some((item) => item.name.toLowerCase() === origin.name.toLowerCase())) {
        throw new Error("multiple installed versions of the same native source package cannot share an artifact directory");
      }
      component = { manager: origin.manager, name: origin.name, version: origin.version,
        license: origin.license, binaries: {}, materials: {} };
      const output = resolve(destination, "qemu-dependencies", origin.name);
      await mkdir(output, { recursive: true });
      await origin.capture(output, component.materials);
      components.set(identity, component);
    }
    component.binaries[binary] = { inputSha256: input.sha256, sha256: await runtimeDigest(resolve(destination, binary)) };
    if (await runtimeDigest(input.path) !== input.sha256) throw new Error("installed QEMU dependency changed during source capture");
  }
  const manifest: DependencyManifest = { formatVersion: 1, components: [...components.values()].sort((a, b) => a.name.localeCompare(b.name)) };
  await writeFile(resolve(destination, "qemu-dependencies.json"), `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx" });
}

interface Origin {
  manager: DependencyComponent["manager"]; name: string; version: string; license: string;
  capture(output: string, materials: Record<string, string>): Promise<void>;
}

async function homebrewOrigin(library: string, cellar: string, scratch: string, run: BuildRunner): Promise<Origin> {
  const actual = await realpath(library), path = relative(cellar, actual).split("/");
  const name = path[0], version = path[1];
  if (name === undefined || version === undefined || path.length < 3 || !safeName.test(name) || !safeName.test(version)) {
    throw new Error("bundled dylib must belong to an exact installed Homebrew keg");
  }
  const keg = resolve(cellar, name, version), formula = resolve(keg, ".brew", `${name}.rb`);
  await regular(formula, 1024 * 1024);
  const data: unknown = JSON.parse(await run("brew", ["info", "--json=v2", "--formula", formula], scratch, true,
    { HOMEBREW_NO_AUTO_UPDATE: "1" }));
  if (!record(data) || !Array.isArray(data.formulae) || data.formulae.length !== 1) throw new Error("invalid installed formula metadata");
  const info = data.formulae[0];
  if (!record(info) || info.name !== name || !record(info.versions) || typeof info.versions.stable !== "string"
    || !Number.isSafeInteger(info.revision) || (info.revision as number) < 0
    || `${info.versions.stable}${info.revision === 0 ? "" : `_${info.revision}`}` !== version
    || !record(info.urls) || !record(info.urls.stable) || typeof info.urls.stable.checksum !== "string"
    || !sha256.test(info.urls.stable.checksum)) throw new Error("formula does not describe the installed keg version");
  const expectedSource = info.urls.stable.checksum;
  const license = licenseExpression(info.license);
  return { manager: "homebrew", name, version, license, async capture(output, materials) {
    await material(formula, output, "formula.rb", materials);
    await material(resolve(keg, "INSTALL_RECEIPT.json"), output, "install-receipt.json", materials);
    const cache = resolve(scratch, `brew-cache-${name}`); await mkdir(cache);
    await run("brew", ["fetch", "--build-from-source", "--formula", formula], scratch, false,
      { HOMEBREW_CACHE: cache, HOMEBREW_NO_AUTO_UPDATE: "1" });
    const downloads = resolve(cache, "downloads"), entries = await readdir(downloads);
    if (entries.length === 0 || entries.length > 96) throw new Error("formula source download count exceeds its bound");
    let primary = false;
    for (const entry of entries.sort()) {
      if (!safeName.test(entry) || entry.endsWith(".incomplete")) throw new Error("incomplete or invalid formula source download");
      const digest = await material(resolve(downloads, entry), output, entry, materials);
      primary ||= digest === expectedSource;
    }
    if (!primary) throw new Error("formula source archive with the installed checksum was not captured");
  } };
}

async function msysOrigin(library: string, scratch: string, run: BuildRunner): Promise<Origin> {
  const unix = (await run("cygpath", ["-u", library], scratch, true)).trim();
  const owner = (await run("pacman", ["-Qqo", "--", unix], scratch, true, { LC_ALL: "C" })).trim();
  if (!safeName.test(owner)) throw new Error("DLL does not have a single installed MSYS2 owner");
  const db = (await run("pacman-conf", ["DBPath"], scratch, true)).trim();
  const local = resolve((await run("cygpath", ["-w", `${db}/local`], scratch, true)).trim());
  const entries = await readdir(local);
  if (entries.length > 4096) throw new Error("MSYS2 package database exceeds its bound");
  const candidates = entries.filter((entry) => entry.startsWith(`${owner}-`));
  let selected: { fields: Map<string, string[]>; path: string } | undefined;
  for (const entry of candidates) {
    const path = resolve(local, entry, "desc"); await regular(path, 65536);
    const fields = pacmanDescription(await readFile(path, "utf8"));
    if (single(fields, "NAME") !== owner) continue;
    if (selected !== undefined) throw new Error("ambiguous installed DLL package");
    selected = { fields, path };
  }
  if (selected === undefined) throw new Error("installed DLL package metadata missing");
  const name = single(selected.fields, "BASE"), version = single(selected.fields, "VERSION");
  if (!safeName.test(name) || !/^(?:[0-9]+:)?[A-Za-z0-9_.+~-]+-[0-9]+$/u.test(version)) throw new Error("invalid MSYS2 source package identity");
  const licenses = selected.fields.get("LICENSE");
  if (licenses === undefined || licenses.length === 0) throw new Error("MSYS2 source package license missing");
  const license = licenses.map(licenseExpression).join(" AND ");
  const description = selected.path;
  const filename = `${name}-${version.replace(/^[0-9]+:/u, "")}.src.tar.zst`;
  return { manager: "msys2", name, version, license, async capture(output, materials) {
    await material(description, output, "installed-package.txt", materials);
    const source = resolve(scratch, filename), signature = `${source}.sig`;
    const url = `https://mirror.msys2.org/mingw/sources/${filename}`;
    for (const [destination, address, limit] of [[source, url, maximumBytes], [signature, `${url}.sig`, 65536]] as const) {
      await run("curl", ["--fail", "--location", "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
        "--max-time", "600", "--max-filesize", String(limit), "--output", destination, address], scratch);
    }
    // Source-only archives are signed by the distribution. Never extract or
    // run a downloaded PKGBUILD on the host to establish its trust.
    const unixSignature = (await run("cygpath", ["-u", signature], scratch, true)).trim();
    const unixSource = (await run("cygpath", ["-u", source], scratch, true)).trim();
    // pacman-key is a shell script, not a Windows PE executable. Arguments
    // cross the MSYS boundary separately; paths are never shell source.
    await run("bash", ["-c", 'exec pacman-key --verify "$@"', "sandsurf-source", unixSignature, unixSource], scratch);
    await material(source, output, filename, materials);
    await material(signature, output, `${filename}.sig`, materials);
  } };
}

export function pacmanDescription(text: string): Map<string, string[]> {
  if (Buffer.byteLength(text) > 65536 || text.includes("\0")) throw new Error("package metadata exceeds its bound");
  const fields = new Map<string, string[]>();
  for (const block of text.trim().split(/\r?\n\r?\n/u)) {
    const lines = block.split(/\r?\n/u), key = /^%([A-Z0-9_]+)%$/u.exec(lines.shift() ?? "")?.[1];
    if (key === undefined || fields.has(key) || lines.some((line) => line.length === 0 || line.length > 4096)) throw new Error("invalid package metadata fields");
    fields.set(key, lines);
  }
  return fields;
}
function single(fields: ReadonlyMap<string, readonly string[]>, key: string): string {
  const values = fields.get(key);
  if (values?.length !== 1) throw new Error(`installed package ${key} is not singular`);
  return values[0]!;
}

export function licenseExpression(value: unknown, depth = 0): string {
  if (depth > 8) throw new Error("license expression nesting exceeds its bound");
  if (typeof value === "string" && /^[A-Za-z0-9().+ -]{1,256}$/u.test(value) && !/unknown|custom|proprietary/iu.test(value)) return value;
  if (record(value) && Object.keys(value).length === 1) {
    for (const [key, items] of Object.entries(value)) {
      if (!['all_of', 'any_of'].includes(key) || !Array.isArray(items) || items.length < 2 || items.length > 16) break;
      return `(${items.map((item) => licenseExpression(item, depth + 1)).join(key === "all_of" ? " AND " : " OR ")})`;
    }
  }
  throw new Error("native library has no distributable license expression");
}

async function material(source: string, output: string, name: string, materials: Record<string, string>): Promise<string> {
  if (!safeName.test(name) || Object.hasOwn(materials, name) || Object.keys(materials).length >= 100) throw new Error("invalid source material name/count");
  await regular(source, maximumBytes);
  const before = await runtimeDigest(source), target = resolve(output, name);
  await copyFile(source, target); await regular(target, maximumBytes);
  if (await runtimeDigest(source) !== before || await runtimeDigest(target) !== before) throw new Error("source material changed during capture");
  materials[name] = before;
  return before;
}

/** A closed source inventory covers every non-system loader dependency and
 * rejects extra archives/recipes as well as references without actual bytes. */
export async function verifyDependencySources(root: string, runtime: Readonly<Record<string, string>>): Promise<DependencyManifest> {
  const path = resolve(root, "qemu-dependencies.json"); await regular(path, 1024 * 1024);
  const value: unknown = JSON.parse(await readFile(path, "utf8"));
  if (!record(value) || Object.keys(value).sort().join(",") !== "components,formatVersion"
    || value.formatVersion !== 1 || !Array.isArray(value.components) || value.components.length > 32) throw new Error("invalid native dependency source manifest");
  const required = new Set(Object.keys(runtime).filter((name) => /(?:\.dll|\.dylib)$/iu.test(name)));
  const names = new Set<string>();
  for (const component of value.components) {
    if (!record(component) || Object.keys(component).sort().join(",") !== "binaries,license,manager,materials,name,version"
      || !['homebrew', 'msys2'].includes(String(component.manager)) || typeof component.name !== "string" || !safeName.test(component.name)
      || typeof component.version !== "string" || !/^[A-Za-z0-9_.+:~-]{1,128}$/u.test(component.version)
      || typeof component.license !== "string" || licenseExpression(component.license) !== component.license
      || !record(component.binaries) || Object.keys(component.binaries).length === 0 || !record(component.materials)
      || Object.keys(component.materials).length === 0 || Object.keys(component.materials).length > 100
      || names.has(component.name.toLowerCase())) throw new Error("invalid native dependency source component");
    names.add(component.name.toLowerCase());
    for (const [binary, identity] of Object.entries(component.binaries)) {
      if (!required.delete(binary) || !record(identity) || Object.keys(identity).sort().join(",") !== "inputSha256,sha256"
        || typeof identity.inputSha256 !== "string" || !sha256.test(identity.inputSha256) || identity.sha256 !== runtime[binary]) {
        throw new Error("native dependency sources do not bind the packaged loader inputs");
      }
    }
    const materials = component.materials;
    const directory = resolve(root, "qemu-dependencies", component.name), info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || JSON.stringify((await readdir(directory)).sort()) !== JSON.stringify(Object.keys(materials).sort())) throw new Error("native dependency source inventory differs");
    let hasArchive = false;
    for (const [name, expected] of Object.entries(materials)) {
      if (!safeName.test(name) || typeof expected !== "string" || !sha256.test(expected)) throw new Error("invalid native dependency source material");
      const file = resolve(directory, name); await regular(file, maximumBytes);
      if (await runtimeDigest(file) !== expected) throw new Error("native dependency source material digest differs");
      hasArchive ||= /\.(?:tar\.(?:xz|gz|bz2|zst)|tgz|zip)$/u.test(name);
    }
    if (!hasArchive || component.manager === "homebrew" && (materials['formula.rb'] === undefined || materials['install-receipt.json'] === undefined)
      || component.manager === "msys2" && (materials['installed-package.txt'] === undefined || !Object.keys(materials).some((name) => name.endsWith('.src.tar.zst.sig')))) {
      throw new Error("native dependency lacks complete source and the installed build recipe binding");
    }
  }
  if (required.size !== 0) throw new Error("packaged native libraries lack corresponding source");
  const directory = resolve(root, "qemu-dependencies");
  if (names.size > 0) {
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || JSON.stringify((await readdir(directory)).map((name) => name.toLowerCase()).sort()) !== JSON.stringify([...names].sort())) throw new Error("undeclared native dependency source package");
  } else {
    try { await lstat(directory); throw new Error("unexpected native dependency source directory"); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
  return value as unknown as DependencyManifest;
}

export function dependencySourceFiles(manifest: DependencyManifest): string[] {
  return ['qemu-dependencies.json', ...manifest.components.flatMap((component) => Object.keys(component.materials)
    .map((name) => `qemu-dependencies/${component.name}/${name}`))].sort();
}
async function regular(path: string, maximum: number): Promise<void> {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size === 0 || info.size > maximum) throw new Error("native source material is not a bounded independent file");
}
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
