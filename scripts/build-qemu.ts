import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ownerHooks, QEMU_CORRESPONDING_FILES, QEMU_SOURCE } from "./qemu-source.ts";
import { qemuRequiredInputs, runtimeDigest, verifyQemuRuntime } from "./qemu-runtime.ts";
import { collectDependencySources, verifyDependencySources } from "./qemu-dependencies.ts";
import type { CommandLimits, LibraryInput } from "./qemu-dependencies.ts";
import { peImports } from "./pe-imports.ts";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Build the product VMM, never a discovered host QEMU or a software-emulation
 * substitute. Separate GPL executable and complete corresponding source.
 * Dependencies are relocated beside it; runtime never uses Homebrew/MSYS PATH.
 */
export async function buildQemu(destination: string): Promise<void> {
  if (!["darwin", "win32"].includes(process.platform) || !["x64", "arm64"].includes(process.arch)
      || (process.platform === "win32" && process.arch !== "x64")) {
    throw new Error("owned QEMU builds require native macOS x64/arm64 or Windows x64");
  }
  destination = resolve(destination);
  const scratch = await mkdtemp(resolve(tmpdir(), "sandsurf-qemu-build-"));
  try {
    const archive = resolve(scratch, `qemu-${QEMU_SOURCE.version}.tar.xz`);
    await run("curl", ["--fail", "--location", "--proto", "=https", "--tlsv1.2", "--silent", "--show-error",
      "--max-time", "600", "--output", archive, QEMU_SOURCE.url], scratch);
    const info = await lstat(archive);
    if (!info.isFile() || info.isSymbolicLink() || info.size !== QEMU_SOURCE.bytes
      || await digest(archive) !== QEMU_SOURCE.sha256) throw new Error("QEMU source differs from the reviewed release");
    // Host tar sees only the pinned trusted tool source, never guest disk data
    // or an OCI layer. Do not execute guest image scripts in this build path.
    // The extractor already runs in this owned directory. Give it the local
    // archive name: GNU tar interprets a Windows drive colon as remote syntax.
    // MSYS link emulation (even nativestrict) first stats the target, rejecting
    // forward/dangling source links. Use the native Windows libarchive owner,
    // which creates actual NTFS links; no copy/cookie or skipped source trees.
    const systemRoot = process.env.SystemRoot;
    if (process.platform === "win32" && systemRoot === undefined) throw new Error("native Windows extraction requires SystemRoot");
    const tar = process.platform === "win32" ? resolve(systemRoot!, "System32/tar.exe") : "tar";
    await run(tar, ["-xJf", basename(archive)], scratch);
    const source = resolve(scratch, `qemu-${QEMU_SOURCE.version}`);
    const main = resolve(source, "system/main.c");
    const whpx = resolve(source, "target/i386/whpx/whpx-all.c");
    const misc = resolve(source, "qapi/misc.json");
    const hooked = ownerHooks(await readFile(main, "utf8"), await readFile(whpx, "utf8"), await readFile(misc, "utf8"),
      await readFile(resolve(repository, "vmm/qemu/sandsurf-qapi.json"), "utf8"));
    await writeFile(main, hooked.main); await writeFile(whpx, hooked.whpx); await writeFile(misc, hooked.misc);
    for (const name of ["sandsurf-entry.c", "sandsurf-entry.h", "sandsurf-whpx.c"]) {
      await copyFile(resolve(repository, "vmm/qemu", name), resolve(source, name));
    }
    const build = resolve(scratch, "build"); await mkdir(build);
    const windows = process.platform === "win32";
    const architecture = process.arch === "arm64" ? "aarch64" : "x86_64";
    const deviceTree: string[] = [];
    if (architecture === "aarch64") {
      // The virt hardware model needs libfdt even when optional features are
      // disabled. Select the installed source-bound library, not an implicit
      // subproject download or another architecture's include/library paths.
      const prefix = (await run("brew", ["--prefix", "dtc"], scratch, true)).trim();
      if (!/^\/(?:opt\/homebrew|usr\/local)\/[A-Za-z0-9_./+-]+$/u.test(prefix)) throw new Error("invalid native libfdt prefix");
      deviceTree.push("--enable-fdt=system", `--extra-cflags=-I${prefix}/include`, `--extra-ldflags=-L${prefix}/lib`);
    }
    await run(windows ? "bash" : "/bin/sh", [shellPath(resolve(source, "configure")),
      `--target-list=${architecture}-softmmu`, "--without-default-features", "--disable-tcg",
      windows ? "--enable-whpx" : "--enable-hvf", "--disable-tools", "--disable-docs",
      ...deviceTree,
      "--disable-plugins", "--disable-slirp", "--disable-guest-agent", "--disable-werror", "--disable-download"], build);
    // One compiler at a time, including in CI. No unbounded host RAM spike.
    const builtExecutable = `qemu-system-${architecture}${windows ? ".exe" : ""}`;
    await run("ninja", ["-j", "1", builtExecutable], build);
    await mkdir(destination, { recursive: true });
    const executable = resolve(destination, `sandsurf-qemu-${process.arch}${windows ? ".exe" : ""}`);
    await copyFile(resolve(build, builtExecutable), executable);
    await chmod(executable, 0o755);
    const libraries = windows ? await windowsLibraries(executable, destination)
      : await darwinLibraries(executable, destination);
    const firmware = resolve(destination, "qemu-runtime/firmware");
    await mkdir(firmware, { recursive: true });
    if (process.arch === "x64") {
      for (const name of ["bios-256k.bin", "linuxboot_dma.bin", "kvmvapic.bin", "pvh.bin"]) {
        await copyFile(resolve(source, "pc-bios", name), resolve(firmware, name));
      }
    }
    // Keep one pristine upstream archive and the complete hook recipe. Release
    // assembly can deduplicate identical source rather than shipping it per VM.
    const corresponding = resolve(destination, "qemu-source"); await mkdir(corresponding);
    for (const path of QEMU_CORRESPONDING_FILES) {
      await mkdir(dirname(resolve(corresponding, path)), { recursive: true });
      const input = path === basename(archive) ? archive
        : ["COPYING", "COPYING.LIB", "LICENSE"].includes(path) ? resolve(source, path) : resolve(repository, path);
      await copyFile(input, resolve(corresponding, path));
    }
    await writeFile(resolve(destination, "qemu-build.json"), `${JSON.stringify({ formatVersion: 1,
      upstream: QEMU_SOURCE, platform: process.platform, architecture: process.arch,
      accelerator: windows ? "whpx" : "hvf", tcg: false }, null, 2)}\n`);
    if (!windows) {
      for (const name of await readdir(resolve(destination, "lib"))) {
        await run("/usr/bin/codesign", ["--force", "--sign", "-", "--options", "runtime", resolve(destination, "lib", name)], build);
      }
      await run("/usr/bin/codesign", ["--force", "--sign", "-", "--options", "runtime",
        "--entitlements", resolve(repository, "vmm/qemu/hvf.entitlements"), executable], build);
    }
    const platform = `${windows ? "windows" : "macos"}-${process.arch}`;
    const inputs = qemuRequiredInputs(platform);
    if (windows) {
      inputs.push(...(await readdir(destination)).filter((name) => name.toLowerCase().endsWith(".dll")));
    } else {
      inputs.push(...(await readdir(resolve(destination, "lib"))).map((name) => `lib/${name}`));
    }
    const files: Record<string, string> = {};
    for (const input of inputs.sort()) files[input] = await runtimeDigest(resolve(destination, input));
    await writeFile(resolve(destination, "qemu-runtime.json"), `${JSON.stringify({ formatVersion: 1,
      architecture: process.arch === "arm64" ? "arm64" : "amd64", qemuVersion: QEMU_SOURCE.version, files }, null, 2)}\n`);
    await collectDependencySources(destination, libraries, scratch, run);
    await verifyDependencySources(destination, await verifyQemuRuntime(destination, platform));
  } finally {
    // Only this invocation's trusted source/build stage is deleted.
    await rm(scratch, { recursive: true, force: true });
  }
}

async function darwinLibraries(executable: string, destination: string): Promise<Map<string, LibraryInput>> {
  const origins = new Map<string, LibraryInput>();
  const libraryRoot = resolve(destination, "lib"); await mkdir(libraryRoot);
  const names = new Map<string, string>();
  const pending = [{ path: executable, executable: true }];
  while (pending.length > 0) {
    const item = pending.shift()!;
    const lines = (await run("/usr/bin/otool", ["-L", item.path], destination, true)).split("\n").slice(1);
    for (const line of lines) {
      const dependency = /^\s+(.+?)\s+\(compatibility version/u.exec(line)?.[1];
      if (dependency === undefined || dependency.startsWith("/usr/lib/") || dependency.startsWith("/System/Library/")) continue;
      // Dylib's own install name is not another dependency. Rebased names are
      // encountered only after this invocation has already copied that node.
      if (dependency === item.path || dependency.startsWith("@rpath/") && basename(dependency) === basename(item.path)) continue;
      if (!dependency.startsWith("/opt/homebrew/") && !dependency.startsWith("/usr/local/")) {
        throw new Error(`unresolved non-system QEMU dependency ${dependency}`);
      }
      const name = basename(dependency);
      if (!/^[A-Za-z0-9_.+-]+\.dylib$/u.test(name)) throw new Error("invalid bundled library name");
      const target = resolve(libraryRoot, name), hash = await digest(dependency);
      if (names.has(name) && names.get(name) !== hash) throw new Error("ambiguous QEMU library basename");
      if (!names.has(name)) {
        names.set(name, hash); origins.set(`lib/${name}`, { path: dependency, sha256: hash });
        await copyFile(dependency, target); await chmod(target, 0o755);
        await run("/usr/bin/install_name_tool", ["-id", `@rpath/${name}`, target], destination);
        pending.push({ path: target, executable: false });
      }
      await run("/usr/bin/install_name_tool", ["-change", dependency,
        `@loader_path/${item.executable ? "lib/" : ""}${name}`, item.path], destination);
    }
  }
  return origins;
}

export async function windowsLibraries(executable: string, destination: string): Promise<Map<string, LibraryInput>> {
  const origins = new Map<string, LibraryInput>();
  const prefix = process.env.MINGW_PREFIX, system = process.env.SystemRoot;
  if (prefix === undefined || system === undefined) throw new Error("QEMU build requires a native MSYS2 UCRT toolchain");
  const binaryRoot = resolve(await run("cygpath", ["-w", `${prefix}/bin`], destination, true).then((value) => value.trim()));
  const pending = [executable], names = new Set<string>();
  while (pending.length > 0) {
    for (const name of await peImports(pending.shift()!)) {
      const key = name.toLowerCase();
      if (names.has(key)) continue;
      names.add(key);
      const source = resolve(binaryRoot, name);
      try { await lstat(source); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        if (key.startsWith("api-ms-win-") || key.startsWith("ext-ms-win-")) continue;
        await lstat(resolve(system, "System32", name)); continue;
      }
      const target = resolve(destination, name);
      origins.set(name, { path: source, sha256: await digest(source) });
      await copyFile(source, target); pending.push(target);
    }
  }
  return origins;
}

function shellPath(path: string): string {
  return process.platform === "win32" ? path.replace(/^([A-Za-z]):/u, (_, drive: string) => `/${drive.toLowerCase()}`).replaceAll("\\", "/") : path;
}
async function digest(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const bytes of createReadStream(path, { highWaterMark: 65536 })) hash.update(bytes);
  return hash.digest("hex");
}
export function run(command: string, args: readonly string[], cwd: string, capture = false,
  environment: Readonly<Record<string, string>> = {}, limits?: Readonly<CommandLimits>): Promise<string> {
  if (limits !== undefined && (!capture || !Number.isSafeInteger(limits.timeoutMs) || limits.timeoutMs < 1
    || limits.timeoutMs > 300000 || !Number.isSafeInteger(limits.maximumOutputBytes)
    || limits.maximumOutputBytes < 1 || limits.maximumOutputBytes > 1024 * 1024)) {
    return Promise.reject(new Error("invalid bounded build-command limits"));
  }
  return new Promise((resolveRun, rejectRun) => {
    let output = "", outputBytes = 0, tooLarge = false, expired = false;
    const maximum = limits?.maximumOutputBytes ?? 1024 * 1024;
    const child = spawn(command, args, { cwd, env: { ...process.env, ...environment }, stdio: capture ? ["ignore", "pipe", "inherit"] : "inherit" });
    // Bounded verifier calls cannot start daemons or subprocesses (--no-autostart).
    // A compiler's whole build tree has a different owner/budget; don't pretend
    // that killing one arbitrary process would contain all its descendants.
    const timer = limits === undefined ? undefined : setTimeout(() => {
      expired = true; child.kill("SIGKILL");
    }, limits.timeoutMs);
    child.stdout?.on("data", (bytes: Buffer) => {
      if (tooLarge || expired) return;
      outputBytes += bytes.length;
      if (outputBytes > maximum) { tooLarge = true; child.kill("SIGKILL"); }
      else output += bytes.toString("utf8");
    });
    child.once("error", error => { clearTimeout(timer); rejectRun(error); });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (code === 0 && !tooLarge && !expired) resolveRun(output);
      else rejectRun(new Error(`${command} failed (${expired ? "deadline" : tooLarge ? "output bound" : code ?? signal ?? "unknown"})`));
    });
  });
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const destination = process.argv[2];
  if (destination === undefined || process.argv.length !== 3) throw new Error("build-qemu requires one owned output directory");
  await buildQemu(destination);
}
