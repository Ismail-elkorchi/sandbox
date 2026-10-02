import { lstat, opendir, realpath } from "node:fs/promises";
import { spawn } from "node:child_process";
import { basename, dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { QEMU_CORRESPONDING_FILES } from "./qemu-source.ts";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const platforms = new Set(["linux-x64", "linux-arm64", "macos-x64", "macos-arm64", "windows-x64"]);
const maximumFileBytes = 512 * 1024 ** 2;

/** Read-only inventory for release verification. Publication and its OS lease
 * belong to the native build tool, never to a separate lock-holder process. */
export async function artifactFiles(root: string, relative = "", depth = 0): Promise<string[]> {
  if (depth > 6) throw new Error("native payload nesting exceeds its bound");
  const directory = await lstat(resolve(root, relative));
  if (!directory.isDirectory() || directory.isSymbolicLink()) throw new Error("native artifact directory is an alias");
  const files: string[] = [];
  let entries = 0;
  for await (const entry of await opendir(resolve(root, relative), { bufferSize: 32 })) {
    if (++entries > 256) throw new Error("native payload directory exceeds its bound");
    if (!/^[A-Za-z0-9_.+-]+$/u.test(entry.name)) throw new Error("invalid native artifact name");
    const child = relative === "" ? entry.name : `${relative}/${entry.name}`;
    const info = await lstat(resolve(root, child));
    if (info.isSymbolicLink()) throw new Error("native artifact is an alias");
    if (info.isDirectory()) files.push(...await artifactFiles(root, child, depth + 1));
    else {
      if (!info.isFile() || info.nlink !== 1 || info.size > maximumFileBytes) throw new Error("native artifact is not a bounded exclusive regular file");
      files.push(child);
    }
    if (files.length > 512) throw new Error("native payload file count exceeds its bound");
  }
  return files.sort();
}

let publisher: Promise<string> | undefined;
function buildPublisher(): Promise<string> {
  // Host-target build tool only. This is not shipped in the npm runtime or
  // coupled to the guest target selected for the platform being published.
  publisher ??= new Promise<string>((resolveBuild, rejectBuild) => {
    const environment = { ...process.env };
    delete environment.CARGO_BUILD_TARGET;
    const child = spawn("cargo", ["build", "--quiet", "-p", "sandsurf-native", "--bin", "sandsurf-artifact-publisher"],
      { cwd: repository, env: environment, stdio: ["ignore", "ignore", "inherit"] });
    child.once("error", rejectBuild);
    child.once("exit", (code, signal) => {
      if (code !== 0 || signal !== null) rejectBuild(new Error(`artifact publisher build failed (${code ?? signal})`));
      else resolveBuild(resolve(repository, environment.CARGO_TARGET_DIR ?? "target", "debug",
        `sandsurf-artifact-publisher${process.platform === "win32" ? ".exe" : ""}`));
    });
  });
  return publisher;
}

async function publish(request: object): Promise<string | undefined> {
  const executable = await buildPublisher();
  return new Promise((resolvePublish, rejectPublish) => {
    const child = spawn(executable, [], { cwd: repository, stdio: ["pipe", "pipe", "pipe"] });
    const output: Buffer[] = [], errors: Buffer[] = [];
    let outputBytes = 0, errorBytes = 0, exceeded = false;
    const capture = (target: "output" | "errors", bytes: Buffer): void => {
      if (exceeded) return;
      const count = target === "output" ? outputBytes : errorBytes;
      if (count + bytes.byteLength > 16384) { exceeded = true; child.kill(); return; }
      if (target === "output") { output.push(bytes); outputBytes += bytes.byteLength; }
      else { errors.push(bytes); errorBytes += bytes.byteLength; }
    };
    child.stdout.on("data", (bytes: Buffer) => capture("output", bytes));
    child.stderr.on("data", (bytes: Buffer) => capture("errors", bytes));
    child.once("error", rejectPublish);
    // An aborted owner can leave only an unpublished stage or a recoverable
    // previous generated tree; neither is a partially published generation.
    child.stdin.on("error", rejectPublish);
    child.once("exit", (code, signal) => {
      if (exceeded || code !== 0 || signal !== null) {
        rejectPublish(new Error(Buffer.concat(errors, errorBytes).toString("utf8").trim() || `native publication failed (${code ?? signal})`)); return;
      }
      try {
        const result: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(output, outputBytes)));
        if (result !== null && (typeof result !== "string" || !isAbsolute(result) || basename(result) !== "native")) {
          throw new Error("invalid native publication result");
        }
        resolvePublish(result === null ? undefined : result as string);
      } catch (error) { rejectPublish(error); }
    });
    child.stdin.end(JSON.stringify(request));
  });
}

/** Whole-tree replacement used for a complete verified release. Displaced
 * generated bytes stay recoverable at the returned backup path. */
export async function publishNativeTree(staged: string, destination: string): Promise<string | undefined> {
  staged = await addressed(staged); destination = await addressed(destination);
  if (basename(destination) !== "native" || dirname(staged) !== dirname(destination) || staged === destination) {
    throw new Error("native publication requires an adjacent staged tree");
  }
  return publish({ kind: "tree", staged, root: destination });
}

/** Read/copy/verify/publish execute under one native OS lease in the same
 * process. Concurrent platform builds cannot lose each other's payloads. */
export async function publishNativePlatform(root: string, platform: string, payload: string, corresponding?: string): Promise<void> {
  root = await addressed(root); payload = await addressed(payload);
  if (basename(root) !== "native" || !platforms.has(platform)) throw new Error("invalid native build publication target");
  await publish({ kind: "platform", root, platform, payload, corresponding: corresponding === undefined ? null : await addressed(corresponding),
    corresponding_files: [...QEMU_CORRESPONDING_FILES].sort() });
}

async function addressed(path: string): Promise<string> {
  path = resolve(path);
  // Normalize system ancestor spellings (notably macOS /var -> /private/var)
  // once. The final object is still checked for links by the native owner.
  return resolve(await realpath(dirname(path)), basename(path));
}
