import { copyFile, lstat, mkdir, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { runtimeDigest } from "./qemu-runtime.ts";
import { evaluateLicense } from "./license-expression.ts";

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
export interface CommandLimits { timeoutMs: number; maximumOutputBytes: number }
export type BuildRunner = (command: string, arguments_: readonly string[], cwd: string, capture?: boolean,
  environment?: Readonly<Record<string, string>>, limits?: Readonly<CommandLimits>) => Promise<string>;

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
  const actual = await realpath(library), path = relative(cellar, actual).split(sep);
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
  const license = msysLicenseExpression(licenses);
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
    // Never extract or run a downloaded PKGBUILD to establish its trust.
    const verified = await verifyMsysSource(source, signature, scratch, run);
    if (await material(source, output, filename, materials) !== verified.source
      || await material(signature, output, `${filename}.sig`, materials) !== verified.signature) {
      throw new Error("verified MSYS2 source changed during capture");
    }
  } };
}

/** Verify against the installed distribution trust database without modifying
 * it, importing keys, or using the user's GnuPG configuration. pacman-key's
 * administrative wrapper checks writable-keyring configuration even for
 * verification. Its underlying trust requirement is retained here, alongside
 * successful exit and one complete, cryptographically valid signature.
 * https://raw.githubusercontent.com/msys2/msys2-pacman/master/scripts/pacman-key.sh.in */
export async function verifyMsysSource(source: string, signature: string, scratch: string,
  run: BuildRunner): Promise<{ source: string; signature: string }> {
  await regular(source, maximumBytes); await regular(signature, 65536);
  requireDetachedSignature(await readFile(signature));
  const verified = { source: await runtimeDigest(source), signature: await runtimeDigest(signature) };
  const keyring = (await run("pacman-conf", ["GPGDir"], scratch, true)).trim();
  if (!keyring.startsWith("/") || keyring.length > 4096 || /[\0\r\n]/u.test(keyring)) {
    throw new Error("installed distribution keyring path is invalid");
  }
  const unixSignature = (await run("cygpath", ["-u", signature], scratch, true)).trim();
  const unixSource = (await run("cygpath", ["-u", source], scratch, true)).trim();
  const status = await run("gpg", ["--no-options", "--homedir", keyring, "--batch", "--no-tty",
    "--no-autostart", "--lock-never", "--no-auto-check-trustdb", "--no-auto-key-retrieve",
    "--auto-key-locate", "clear", "--trust-model", "pgp", "--status-fd", "1",
    "--verify", unixSignature, unixSource], scratch, true, {}, { timeoutMs: 30000, maximumOutputBytes: 65536 });
  requireTrustedSignature(status);
  if (await runtimeDigest(source) !== verified.source || await runtimeDigest(signature) !== verified.signature) {
    throw new Error("MSYS2 source changed during verification");
  }
  return verified;
}

/** Admit one finite signature packet, not a compressed/literal/encrypted
 * OpenPGP message which could expand before the verifier's output cap applies.
 * Packet headers are upstream OpenPGP encodings, not Sandsurf format versions.
 * Cryptographic validity and distribution trust still belong to GPG.
 * https://www.rfc-editor.org/rfc/rfc9580.html#section-4.2 */
export function requireDetachedSignature(bytes: Buffer): void {
  if (bytes.length < 3 || bytes.length > 65536) throw new Error("detached signature packet exceeds its bound");
  const first = bytes[0]!;
  let start: number, length: number;
  if (first === 0xc2) {
    const kind = bytes[1]!;
    if (kind < 192) { start = 2; length = kind; }
    else if (kind < 224 && bytes.length >= 3) { start = 3; length = (kind - 192) * 256 + bytes[2]! + 192; }
    else if (kind === 255 && bytes.length >= 6) { start = 6; length = bytes.readUInt32BE(2); }
    else throw new Error("detached signatures cannot have partial packet lengths");
  } else if (first >= 0x88 && first <= 0x8a) {
    start = 2 + (first === 0x89 ? 1 : first === 0x8a ? 3 : 0);
    if (bytes.length < start) throw new Error("truncated detached signature header");
    length = bytes.readUIntBE(1, start - 1);
  } else throw new Error("MSYS2 source requires one binary detached signature packet");
  if (length === 0 || start + length !== bytes.length) throw new Error("detached signature packet is truncated or has trailing packets");
}

/** Status-fd is a protocol, not localized diagnostics or an exit-code-only
 * success indication. A valid signature from an unknown key is insufficient.
 * Reject extra signatures and every failure/unknown status, even after trust.
 * https://raw.githubusercontent.com/gpg/gnupg/master/doc/DETAILS */
export function requireTrustedSignature(status: string): void {
  if (!status.endsWith("\n") || Buffer.byteLength(status) > 65536
    || /[\x00-\x09\x0b\x0c\x0e-\x1f\x7f]/u.test(status)) throw new Error("invalid signature status bounds");
  const lines = status.replaceAll("\r\n", "\n").split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (lines.length === 0 || lines.length > 64) throw new Error("invalid signature status count");
  let started = false, good: string | undefined, valid: string | undefined, trusted = false;
  for (const line of lines) {
    const fields = /^\[GNUPG:\] ([A-Z_]+)(?: (.*))?$/u.exec(line);
    if (fields === null || Buffer.byteLength(line) > 4096) throw new Error("invalid signature status record");
    const tag = fields[1], args = fields[2] ?? "";
    if (tag === "NEWSIG" && !started) { started = true; continue; }
    if (!started) throw new Error("signature status has no signature boundary");
    if (tag === "KEY_CONSIDERED" && /^(?:[A-F0-9]{40}|[A-F0-9]{64}) [0-9]+$/u.test(args)
      || tag === "SIG_ID" && /^[A-Za-z0-9+/=]+ [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]+$/u.test(args)) continue;
    if (tag === "GOODSIG" && good === undefined && valid === undefined && !trusted) {
      const signer = /^([A-F0-9]{16}|[A-F0-9]{40}|[A-F0-9]{64}) .+$/u.exec(args)?.[1];
      if (signer !== undefined) { good = signer; continue; }
    }
    if (tag === "VALIDSIG" && good !== undefined && valid === undefined && !trusted) {
      const fingerprint = /^((?:[A-F0-9]{40}|[A-F0-9]{64})) [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]+ [0-9]+ [0-9]+ 0 [0-9]+ [0-9]+ 00(?: (?:[A-F0-9]{40}|[A-F0-9]{64}))?$/u.exec(args)?.[1];
      if (fingerprint !== undefined && (fingerprint === good || fingerprint.endsWith(good))) { valid = fingerprint; continue; }
    }
    if ((tag === "TRUST_FULLY" || tag === "TRUST_ULTIMATE") && valid !== undefined && !trusted
      && /^0 pgp(?: [^ ]+)?$/u.test(args)) { trusted = true; continue; }
    throw new Error(`source signature status is not trusted: ${tag}`);
  }
  if (valid === undefined || !trusted) throw new Error("source signature lacks cryptographic validity and distribution trust");
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
  if (typeof value === "string") {
    const named = (id: string) => {
      if (/unknown|custom|proprietary|LicenseRef/iu.test(id)) throw new Error("native library license requires unresolved terms");
      return true;
    };
    if (value.length <= 256 && evaluateLicense(value, named, named)) return value;
    throw new Error("native library lacks an explicit supported license expression");
  }
  if (record(value) && Object.keys(value).length === 1) {
    for (const [key, items] of Object.entries(value)) {
      if (!['all_of', 'any_of'].includes(key) || !Array.isArray(items) || items.length < 2 || items.length > 16) break;
      return licenseExpression(`(${items.map((item) => licenseExpression(item, depth + 1)).join(key === "all_of" ? " AND " : " OR ")})`, depth);
    }
  }
  throw new Error("native library has no distributable license expression");
}

/** MSYS2's installed metadata uses spdx: expressions. Separate array entries
 * are alternatives, not cumulative obligations. Mixed/custom legacy labels
 * have undefined semantics and cannot authorize this closed distribution.
 * https://www.msys2.org/dev/package-licensing/#the-license-array-field */
export function msysLicenseExpression(values: readonly string[]): string {
  if (values.length === 0 || values.length > 16 || values.some((value) => !value.startsWith("spdx:"))) {
    throw new Error("installed MSYS2 package requires explicit SPDX license expressions");
  }
  const expressions = values.map((value) => licenseExpression(value.slice(5)));
  return licenseExpression(expressions.length === 1 ? expressions[0]! : `(${expressions.map((value) => `(${value})`).join(" OR ")})`);
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
