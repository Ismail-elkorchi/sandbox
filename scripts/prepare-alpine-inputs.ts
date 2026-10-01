// Repository bytes are host data. Only the network-disabled libguestfs VM
// unpacks the pinned root, solves dependencies, verifies APKs, or runs scripts.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { chmod, copyFile, lstat, mkdir, mkdtemp, open, realpath, rename, rm, writeFile } from "node:fs/promises";
import { get } from "node:https";
import { isAbsolute, join, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { Transform } from "node:stream";
import { fileURLToPath } from "node:url";

export const REQUIRED_PACKAGES = Object.freeze([
  "alpine-base", "ca-certificates", "busybox-extras", "git", "openrc", "sudo",
  "e2fsprogs", "e2fsprogs-extra", "openssh", "linux-virt", "mkinitfs",
]);
const ORIGIN = "https://dl-cdn.alpinelinux.org";
const SERIES = `${ORIGIN}/alpine/v3.24`;
const VERSION = "3.24.2";
const TARGETS = {
  x64: { apk: "x86_64", qemu: "/usr/bin/qemu-system-x86_64", rootDigest: "c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677" },
  arm64: { apk: "aarch64", qemu: "/usr/bin/qemu-system-aarch64", rootDigest: "9bf70a7f18ea44094cbb5f70c58f9af129c8214745743db0e68e5502cc2ce773" },
} as const;
type Architecture = keyof typeof TARGETS;
export interface Options {
  architecture: Architecture;
  output: string;
  temporaryDirectory: string;
  minirootfs?: string;
}
export interface SelectedPackage { repository: "main" | "community"; basename: string; url: string }
const MAX_PACKAGES = 512;
const MAX_TEXT = 256 * 1024;
const MAX_APK = 128 * 1024 * 1024;
const MAX_TOTAL = 512 * 1024 * 1024;
const PACKAGE_NAME = /^[a-z0-9][a-z0-9+_.-]{0,127}$/u;
const PACKAGE_VERSION = /^[0-9][A-Za-z0-9+_.:~\-]{0,127}$/u;
const APK_BASENAME = /^[a-z0-9][a-z0-9+_.-]{0,127}-[0-9][A-Za-z0-9+_.~\-]{0,127}\.apk$/u;

function absolutePath(value: string): string {
  if (!isAbsolute(value) || value.length > 4096 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error("paths must be bounded absolute paths without control characters");
  }
  return resolve(value);
}

export function parseArguments(args: readonly string[]): Options {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index]; const value = args[index + 1];
    if (key === undefined || !["--architecture", "--output", "--temporary-directory", "--minirootfs"].includes(key) ||
        value === undefined || value.startsWith("--") || values.has(key)) {
      throw new Error("usage: node scripts/prepare-alpine-inputs.ts --architecture x64|arm64 --output /absolute/new-directory [--temporary-directory /disk/directory] [--minirootfs /pinned/archive.tar.gz]");
    }
    values.set(key, value);
  }
  const architecture = values.get("--architecture");
  if (architecture !== "x64" && architecture !== "arm64") throw new Error("--architecture x64|arm64 is required explicitly");
  const output = values.get("--output");
  if (output === undefined) throw new Error("--output is required");
  const minirootfs = values.get("--minirootfs");
  return {
    architecture, output: absolutePath(output),
    temporaryDirectory: absolutePath(values.get("--temporary-directory") ?? "/var/tmp"),
    ...(minirootfs === undefined ? {} : { minirootfs: absolutePath(minirootfs) }),
  };
}

export function assertNativeTarget(architecture: Architecture, platform = process.platform, hostArchitecture = process.arch): void {
  if (platform !== "linux" || hostArchitecture !== architecture) {
    throw new Error(`native Linux ${architecture} with KVM is required; cross-architecture APK execution is unqualified and unsupported (host ${platform}/${hostArchitecture})`);
  }
}

// These are APK's selected local repository URLs, not dependency/version guesses.
// Reject every character that could change a URL, guest path, or tar operand.
export function parseSelectedPackages(text: string, architecture: Architecture): SelectedPackage[] {
  if (Buffer.byteLength(text) > MAX_TEXT || !text.endsWith("\n")) throw new Error("APK selection is oversized or incomplete");
  const lines = text.slice(0, -1).split("\n");
  if (lines.length === 0 || lines.length > MAX_PACKAGES) throw new Error("APK selection count exceeds bound");
  const packages: SelectedPackage[] = [];
  const seen = new Set<string>();
  for (const line of lines) {
    const match = /^(?:file:\/\/)?\/inputs\/(main|community)\/([^/]+)\/([^/]+)$/u.exec(line);
    if (match === null || match[2] !== TARGETS[architecture].apk || !APK_BASENAME.test(match[3] ?? "")) {
      throw new Error(`APK selected an unexpected local repository path: ${line.slice(0, 256)}`);
    }
    const repository = match[1] as "main" | "community"; const basename = match[3]!;
    if (seen.has(basename)) throw new Error("APK selection has duplicate or colliding basenames");
    seen.add(basename);
    packages.push({ repository, basename, url: `${SERIES}/${repository}/${TARGETS[architecture].apk}/${basename}` });
  }
  return packages.sort((left, right) => Buffer.from(left.basename).compare(Buffer.from(right.basename)));
}

export function validatePackageLock(text: string): string[] {
  if (Buffer.byteLength(text) > MAX_TEXT || !text.endsWith("\n")) throw new Error("installed lock is oversized or incomplete");
  const lines = text.slice(0, -1).split("\n");
  if (lines.length === 0 || lines.length > MAX_PACKAGES) throw new Error("installed package count exceeds bound");
  const names = new Set<string>();
  let previous: string | undefined;
  for (const line of lines) {
    const [name, version, extra] = line.split("=");
    if (name === undefined || version === undefined || extra !== undefined || !PACKAGE_NAME.test(name) || !PACKAGE_VERSION.test(version) ||
        names.has(name) || (previous !== undefined && Buffer.from(previous).compare(Buffer.from(line)) >= 0)) {
      throw new Error("installed lock must contain unique, sorted P=V records");
    }
    previous = line; names.add(name);
  }
  for (const name of REQUIRED_PACKAGES) if (!names.has(name)) throw new Error(`installed closure lacks ${name}`);
  return lines;
}

export async function digestFile(path: string, maximum: number): Promise<{ sha256: string; bytes: number }> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.size <= 0 || metadata.size > maximum) throw new Error("input must be a nonempty bounded regular file");
  const hash = createHash("sha256"); let bytes = 0;
  for await (const chunk of createReadStream(path)) {
    bytes += chunk.length;
    if (bytes > maximum) throw new Error("input grew beyond its bound");
    hash.update(chunk);
  }
  if (bytes !== metadata.size) throw new Error("input changed length");
  return { sha256: hash.digest("hex"), bytes };
}

// No redirects, ambient proxy, alternate mirror, or plaintext transport.
async function download(url: string, destination: string, maximum: number, accountBytes?: (bytes: number) => void): Promise<{ sha256: string; bytes: number }> {
  const parsed = new URL(url);
  if (parsed.origin !== ORIGIN || parsed.username || parsed.password || parsed.search || parsed.hash ||
      !parsed.pathname.startsWith("/alpine/v3.24/")) throw new Error("download must use the explicit official Alpine TLS origin");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("Alpine download exceeded 300 seconds")), 300_000);
  let bytes = 0; const hash = createHash("sha256");
  try {
    await new Promise<void>((resolveDownload, rejectDownload) => {
      const request = get(url, { signal: controller.signal }, (response) => {
        const size = response.headers["content-length"];
        if (response.statusCode !== 200 || (size !== undefined && (!/^[0-9]+$/u.test(size) || Number(size) > maximum))) {
          response.destroy(); rejectDownload(new Error(`Alpine download refused status/length for ${url}`)); return;
        }
        const bounded = new Transform({ transform(chunk: Buffer, _encoding, callback) {
          bytes += chunk.length;
          if (bytes > maximum) { callback(new Error("Alpine download exceeds byte bound")); return; }
          try { accountBytes?.(chunk.length); } catch (error) { callback(error as Error); return; }
          hash.update(chunk); callback(null, chunk);
        } });
        pipeline(response, bounded, createWriteStream(destination, { flags: "wx", mode: 0o600 }), { signal: controller.signal })
          .then(() => bytes > 0 ? resolveDownload() : rejectDownload(new Error("empty Alpine download")), rejectDownload);
      });
      request.setTimeout(30_000, () => request.destroy(new Error("Alpine download stalled")));
      request.on("error", rejectDownload);
    });
    return { sha256: hash.digest("hex"), bytes };
  } finally { clearTimeout(timer); }
}

async function protectedTool(path: string): Promise<void> {
  const canonical = await realpath(path);
  const metadata = await lstat(canonical);
  if (!metadata.isFile() || metadata.uid !== 0 || (metadata.mode & 0o022) !== 0 || (metadata.mode & 0o111) === 0) {
    throw new Error(`requires protected system executable ${path}`);
  }
  // Distribution-managed executable symlinks (e.g. coreutils timeout) are
  // allowed only when both the link and its resolved ancestry are protected.
  for (const candidate of [path, canonical]) {
    let current = candidate;
    for (;;) {
      const entry = await lstat(current);
      if (entry.uid !== 0 || (!entry.isSymbolicLink() && (entry.mode & 0o022) !== 0)) throw new Error(`unprotected tool path ${current}`);
      if (current === "/") break;
      current = resolve(current, "..");
    }
  }
}

function run(command: string, args: readonly string[], environment: Record<string, string>, maximum = MAX_TEXT): Promise<string> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, { env: environment, stdio: ["ignore", "pipe", "pipe"], detached: true });
    const output: Buffer[] = []; const errors: Buffer[] = []; let outputBytes = 0; let errorBytes = 0;
    function exceeded(): void {
      if (child.pid !== undefined) { try { process.kill(-child.pid, "SIGKILL"); } catch { /* already exited */ } }
      rejectRun(new Error("isolated tool exceeded output bound"));
    }
    child.stdout.on("data", (chunk: Buffer) => { outputBytes += chunk.length; if (outputBytes > maximum) exceeded(); else output.push(chunk); });
    child.stderr.on("data", (chunk: Buffer) => { errorBytes += chunk.length; if (errorBytes > MAX_TEXT) exceeded(); else errors.push(chunk); });
    child.on("error", rejectRun);
    child.on("close", (code, signal) => {
      if (code !== 0) rejectRun(new Error(`isolated tool failed (${code ?? signal}): ${Buffer.concat(errors).toString("utf8").slice(-8192)}`));
      else resolveRun(Buffer.concat(output).toString("utf8"));
    });
  });
}

type GuestCommand = readonly string[];
function toolEnvironment(temporary: string): Record<string, string> {
  return { PATH: "/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C", LC_ALL: "C", TZ: "UTC", TMPDIR: temporary };
}
async function appliance(disk: string, temporary: string, architecture: Architecture, commands: readonly GuestCommand[]): Promise<string> {
  const args = ["--signal=KILL", "120", "/usr/bin/guestfish", "--no-progress-bars", "--format=raw", "-a", disk,
    "set-pgroup", "false", ":", "set-network", "false", ":", "run"];
  for (const tokens of commands) {
    if (tokens.length === 0 || tokens.some((token) => token.includes("\0") || token === ":" || token.length > 8192)) throw new Error("invalid guest command envelope");
    args.push(":", ...tokens);
  }
  return run("/usr/bin/timeout", args, {
    ...toolEnvironment(temporary), LIBGUESTFS_BACKEND: "direct", LIBGUESTFS_BACKEND_SETTINGS: "force_kvm",
    LIBGUESTFS_MEMSIZE: "512", LIBGUESTFS_HV: TARGETS[architecture].qemu,
  });
}

export const SOLVE_SCRIPT = `#!/bin/sh
set -eu
export LC_ALL=C
# Keep bootstrap world packages too; fetch uses the real APK solver, including
# virtual providers and version constraints, against signed local indexes.
apk --no-network --repositories-file /inputs/repositories fetch --recursive --simulate --url ${REQUIRED_PACKAGES.join(" ")} $(cat /etc/apk/world) > /inputs/selected
cat /inputs/selected
`;
export const VALIDATE_SCRIPT = `#!/bin/sh
set -eu
export LC_ALL=C
# Each signature is checked with the trusted keys from the pinned minirootfs.
apk --no-network --repositories-file /dev/null verify /var/cache/apk/*.apk > /inputs/signatures
# Mirror the builder's explicit local-file installation. Scripts run in this VM.
apk --no-network --cache-dir /var/cache/apk --repositories-file /dev/null add /var/cache/apk/*.apk > /inputs/install-log 2>&1
apk info -e ${REQUIRED_PACKAGES.join(" ")} > /dev/null
# APK's installed database is authoritative; no host version reconstruction.
awk '/^P:/ {p=substr($0,3)} /^V:/ {print p "=" substr($0,3)}' /lib/apk/db/installed | sort > /inputs/package-lock
cat /inputs/package-lock
`;

export async function createPackageArchive(directory: string, output: string, packages: readonly SelectedPackage[], temporary: string): Promise<void> {
  if (packages.length === 0 || packages.length > MAX_PACKAGES || new Set(packages.map((entry) => entry.basename)).size !== packages.length ||
      packages.some((entry) => !APK_BASENAME.test(entry.basename))) throw new Error("unsafe package archive operands");
  await protectedTool("/usr/bin/tar");
  await run("/usr/bin/timeout", ["--signal=KILL", "120", "/usr/bin/tar", "--create", "--gzip", "--format=ustar",
    "--owner=0", "--group=0", "--numeric-owner", "--mtime=@0", "--mode=0644", "--file", output, "--directory", directory,
    "--", ...packages.map((entry) => `var/cache/apk/${entry.basename}`)], toolEnvironment(temporary));
}

export async function prepare(options: Options): Promise<Record<string, string>> {
  assertNativeTarget(options.architecture);
  const target = TARGETS[options.architecture];
  const output = absolutePath(options.output); const temporaryDirectory = absolutePath(options.temporaryDirectory);
  if (options.minirootfs !== undefined) absolutePath(options.minirootfs);
  try { await lstat(output); throw new Error("output directory already exists; choose a new destination"); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  for (const path of ["/usr/bin/guestfish", "/usr/bin/timeout", "/usr/bin/tar", target.qemu]) await protectedTool(path);
  const temporary = await mkdtemp(join(temporaryDirectory, "sandsurf-alpine-inputs-"));
  let publication: string | undefined;
  try {
    const root = join(temporary, "minirootfs.tar.gz");
    const rootUrl = `${SERIES}/releases/${target.apk}/alpine-minirootfs-${VERSION}-${target.apk}.tar.gz`;
    console.error("Staging pinned Alpine root and bounded official repository indexes as data");
    if (options.minirootfs !== undefined) {
      await digestFile(options.minirootfs, 16 * 1024 * 1024);
      await copyFile(options.minirootfs, root);
    } else await download(rootUrl, root, 16 * 1024 * 1024);
    if ((await digestFile(root, 16 * 1024 * 1024)).sha256 !== target.rootDigest) throw new Error("pinned Alpine minirootfs digest mismatch");
    const indexes: { repository: string; url: string; sha256: string; bytes: number }[] = [];
    const downloads = await Promise.allSettled((["main", "community"] as const).map(async (repository) => {
      const url = `${SERIES}/${repository}/${target.apk}/APKINDEX.tar.gz`;
      return { repository, url, ...await download(url, join(temporary, `${repository}-index.tar.gz`), 16 * 1024 * 1024) };
    }));
    for (const result of downloads) { if (result.status === "rejected") throw result.reason; indexes.push(result.value); }
    const solve = join(temporary, "solve.sh"); const validate = join(temporary, "validate.sh");
    await writeFile(solve, SOLVE_SCRIPT, { mode: 0o600 }); await writeFile(validate, VALIDATE_SCRIPT, { mode: 0o600 });
    const disk = join(temporary, "appliance.raw");
    const handle = await open(disk, "wx", 0o600);
    try { await handle.truncate(2 * 1024 * 1024 * 1024); } finally { await handle.close(); }
    console.error("Solving the package closure inside the network-disabled KVM appliance");
    const selection = await appliance(disk, temporary, options.architecture, [
      ["mkfs", "ext4", "/dev/sda"], ["mount-options", "rw", "/dev/sda", "/"],
      ["tar-in", root, "/", "compress:gzip"],
      ["mkdir-p", `/inputs/main/${target.apk}`], ["mkdir-p", `/inputs/community/${target.apk}`],
      ["upload", join(temporary, "main-index.tar.gz"), `/inputs/main/${target.apk}/APKINDEX.tar.gz`],
      ["upload", join(temporary, "community-index.tar.gz"), `/inputs/community/${target.apk}/APKINDEX.tar.gz`],
      ["write", "/inputs/repositories", "/inputs/main\n/inputs/community\n"],
      ["upload", solve, "/inputs/solve.sh"], ["command", "/bin/sh /inputs/solve.sh"],
      ["sync"],
    ]);
    // guestfish's command adds one framing newline after the program's bytes.
    const selected = parseSelectedPackages(selection.replace(/\n$/u, ""), options.architecture);
    const archiveTree = join(temporary, "archive");
    await mkdir(join(archiveTree, "var/cache/apk"), { recursive: true, mode: 0o700 });
    const materials: { basename: string; url: string; sha256: string; bytes: number }[] = [];
    let total = 0;
    let received = 0;
    console.error(`Downloading exactly ${selected.length} solver-selected signed APKs as host data`);
    // Small bounded batches; wait for every request before cleanup on failure.
    for (let offset = 0; offset < selected.length; offset += 4) {
      const batch = await Promise.allSettled(selected.slice(offset, offset + 4).map(async (entry) => ({
        basename: entry.basename, url: entry.url,
        ...await download(entry.url, join(archiveTree, "var/cache/apk", entry.basename), MAX_APK, (bytes) => {
          received += bytes;
          if (received > MAX_TOTAL) throw new Error("APK closure exceeds total download bound");
        }),
      })));
      for (const result of batch) {
        if (result.status === "rejected") throw result.reason;
        total += result.value.bytes;
        if (total > MAX_TOTAL) throw new Error("APK closure exceeds total download bound");
        materials.push(result.value);
      }
    }
    const archive = join(temporary, "alpine-packages.tar.gz");
    await createPackageArchive(archiveTree, archive, selected, temporary);
    console.error("Verifying all APK signatures and installing offline inside the appliance");
    const lockOutput = await appliance(disk, temporary, options.architecture, [
      ["mount-options", "rw", "/dev/sda", "/"], ["tar-in", archive, "/", "compress:gzip"],
      ["upload", validate, "/inputs/validate.sh"], ["command", "/bin/sh /inputs/validate.sh"],
      ["sync"],
    ]);
    const lock = lockOutput.replace(/\n$/u, "");
    const installed = validatePackageLock(lock);
    // Require every installed version, including bootstrap packages, to be
    // carried in the signed archive. This is name formatting, not solving.
    const basenames = new Set(selected.map((entry) => entry.basename));
    for (const record of installed) {
      const [name, version] = record.split("=");
      if (!basenames.has(`${name}-${version}.apk`)) throw new Error(`installed package missing from selected archive: ${record}`);
    }
    const packageLock = join(temporary, "alpine-package-lock");
    await writeFile(packageLock, lock, { mode: 0o600 });
    const archiveDigest = await digestFile(archive, MAX_TOTAL + 16 * 1024 * 1024);
    const lockDigest = await digestFile(packageLock, MAX_TEXT);
    const environment = {
      SANDSURF_IMAGE_ARCHITECTURE: options.architecture,
      SANDSURF_ALPINE_PACKAGES_ARCHIVE: join(output, "alpine-packages.tar.gz"),
      SANDSURF_ALPINE_PACKAGES_SHA256: archiveDigest.sha256,
      SANDSURF_ALPINE_PACKAGE_LOCK: join(output, "alpine-package-lock"),
      SANDSURF_ALPINE_PACKAGE_LOCK_SHA256: lockDigest.sha256,
    };
    // No outputs become visible until offline verification and installation
    // succeed. Publish one directory containing both digest-bound inputs.
    publication = await mkdtemp(join(resolve(output, ".."), ".alpine-inputs-"));
    await copyFile(archive, join(publication, "alpine-packages.tar.gz"));
    await copyFile(packageLock, join(publication, "alpine-package-lock"));
    await writeFile(join(publication, "provenance.json"), `${JSON.stringify({
      format: "sandsurf-alpine-inputs-v1", architecture: options.architecture, alpineVersion: VERSION,
      root: { url: rootUrl, sha256: target.rootDigest }, indexes, packages: materials,
      installedPackages: installed.length, execution: { backend: "libguestfs-direct", accelerator: "KVM", memoryMiB: 512, network: false },
      environment,
    }, null, 2)}\n`, { mode: 0o600 });
    await writeFile(join(publication, "inputs.json"), `${JSON.stringify(environment, null, 2)}\n`, { mode: 0o600 });
    for (const name of ["alpine-packages.tar.gz", "alpine-package-lock", "provenance.json", "inputs.json"]) {
      const path = join(publication, name); await chmod(path, 0o444);
      const file = await open(path, "r"); try { await file.sync(); } finally { await file.close(); }
    }
    const stagedDirectory = await open(publication, "r");
    try { await stagedDirectory.sync(); } finally { await stagedDirectory.close(); }
    await rename(publication, output); publication = undefined;
    const parentDirectory = await open(resolve(output, ".."), "r");
    try { await parentDirectory.sync(); } finally { await parentDirectory.close(); }
    console.error(`Published ${selected.length} verified APKs and ${installed.length} installed P=V records`);
    return environment;
  } finally {
    if (publication !== undefined) await rm(publication, { recursive: true, force: true });
    await rm(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(await prepare(parseArguments(process.argv.slice(2))), null, 2)); }
  catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; }
}
