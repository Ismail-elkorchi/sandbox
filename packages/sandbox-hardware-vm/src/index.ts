import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export interface HardwareVmExtensionRegistration {
  readonly kind: "hardware-vm";
  readonly descriptorPath: string;
  readonly descriptorDigest: string;
}

export interface HardwareVmImageReference {
  readonly manifestPath: string;
  readonly trust: "bundled";
  readonly digest: string;
}

export interface HardwareVmArtifactEntry {
  path: string;
  kind: "directory" | "regular-file" | "symbolic-link";
  mode: number;
  modifiedUnixMs: number;
  contentHex?: string;
  linkTarget?: string;
  sha256?: string;
}

export interface HardwareVmChangeBaseEntry {
  path: string;
  kind: HardwareVmArtifactEntry["kind"];
  sha256?: string;
  mode: number;
  modifiedUnixMs: number;
  linkTarget?: string;
}

export type HardwareVmChangeOperation =
  | { kind: "upsert"; entry: HardwareVmArtifactEntry }
  | { kind: "delete"; path: string }
  | { kind: "rename"; from: string; to: string };

export interface HardwareVmChangeSet {
  formatVersion: 1;
  baseManifestDigest: string;
  base: readonly HardwareVmChangeBaseEntry[];
  operations: readonly HardwareVmChangeOperation[];
  digest: string;
}

export interface HardwareVmApplyReport {
  applied: number;
  recovered: boolean;
  journalPath: string;
}

export class HardwareVmChangeSetApplyError extends Error {
  readonly kind: "conflict" | "invalid" | "io" | "runtime";

  constructor(kind: HardwareVmChangeSetApplyError["kind"], message: string) {
    super(message);
    this.name = "HardwareVmChangeSetApplyError";
    this.kind = kind;
  }
}

export function hardwareVmExtension(): HardwareVmExtensionRegistration {
  if (process.platform !== "linux" || process.arch !== "x64") {
    throw new Error(`the Firecracker extension does not support ${process.platform}-${process.arch}`);
  }
  const packageDirectory = dirname(fileURLToPath(import.meta.url));
  const nativeDirectory = resolve(packageDirectory, "../native", `linux-${process.arch}`);
  const descriptorPath = resolve(nativeDirectory, "extension.json");
  const digestManifestPath = resolve(packageDirectory, "../native/manifest.json");
  const digestManifest: unknown = JSON.parse(readFileSync(digestManifestPath, "utf8"));
  const descriptorDigest = descriptorDigestFromManifest(
    digestManifest,
    `linux-${process.arch}/extension.json`,
  );
  const actual = createHash("sha256").update(readFileSync(descriptorPath)).digest("hex");
  if (actual !== descriptorDigest) throw new Error("hardware-VM extension descriptor digest mismatch");
  return { kind: "hardware-vm", descriptorPath, descriptorDigest };
}

export function minimalHardwareVmImage(): HardwareVmImageReference {
  if (process.platform !== "linux" || process.arch !== "x64") {
    throw new Error(`the minimal Firecracker image does not support ${process.platform}-${process.arch}`);
  }
  const packageDirectory = dirname(fileURLToPath(import.meta.url));
  const manifestPath = resolve(packageDirectory, "../images/minimal-x64/manifest.json");
  const digestManifestPath = resolve(packageDirectory, "../native/manifest.json");
  const digestManifest: unknown = JSON.parse(readFileSync(digestManifestPath, "utf8"));
  const digest = descriptorDigestFromManifest(digestManifest, "images/minimal-x64/manifest.json");
  const actual = createHash("sha256").update(readFileSync(manifestPath)).digest("hex");
  if (actual !== digest) throw new Error("hardware-VM image manifest digest mismatch");
  return { manifestPath, trust: "bundled", digest };
}

export async function applyHardwareVmChangeSet(options: {
  rootPath: string;
  recoveryDirectory: string;
  changeSet: HardwareVmChangeSet;
}): Promise<HardwareVmApplyReport> {
  return runChangeSetTool(
    ["--apply-change-set", absolutePath(options.rootPath, "rootPath"), absolutePath(options.recoveryDirectory, "recoveryDirectory")],
    JSON.stringify(options.changeSet),
  );
}

export async function recoverHardwareVmChangeSet(journalPath: string): Promise<HardwareVmApplyReport> {
  return runChangeSetTool(["--recover-change-set", absolutePath(journalPath, "journalPath")], "");
}

export async function recoverHardwareVmChangeSets(recoveryDirectory: string): Promise<readonly HardwareVmApplyReport[]> {
  const directory = absolutePath(recoveryDirectory, "recoveryDirectory");
  const names = (await readdir(directory))
    .filter((name) => /^apply-[0-9]+-[0-9]+\.json$/u.test(name))
    .sort();
  const reports: HardwareVmApplyReport[] = [];
  for (const name of names) reports.push(await recoverHardwareVmChangeSet(resolve(directory, name)));
  return reports;
}

async function runChangeSetTool(arguments_: readonly string[], input: string): Promise<HardwareVmApplyReport> {
  const runtimeDescriptor = verifiedRuntimeDescriptor();
  const runtime = openSync(runtimeDescriptor.path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = fstatSync(runtime);
    if (!metadata.isFile() || (metadata.mode & 0o111) === 0) {
      throw new HardwareVmChangeSetApplyError("runtime", "hardware-VM runtime is not an executable regular file");
    }
    const actual = createHash("sha256").update(readFileSync(runtime)).digest("hex");
    if (actual !== runtimeDescriptor.sha256) {
      throw new HardwareVmChangeSetApplyError("runtime", "extension runtime digest mismatch");
    }
    const child = spawn("/proc/self/fd/3", arguments_, {
      stdio: ["pipe", "pipe", "pipe", runtime],
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    });
    const output: Buffer[] = [];
    const errors: Buffer[] = [];
    let outputBytes = 0;
    let errorBytes = 0;
    const stdin = child.stdin;
    const stdout = child.stdout;
    const stderr = child.stderr;
    if (stdin === null || stdout === null || stderr === null) {
      child.kill("SIGKILL");
      throw new HardwareVmChangeSetApplyError("runtime", "change-set runtime pipes are unavailable");
    }
    stdout.on("data", (chunk: Buffer) => {
      outputBytes += chunk.byteLength;
      if (outputBytes <= 1024 * 1024) output.push(Buffer.from(chunk));
      else child.kill("SIGKILL");
    });
    stderr.on("data", (chunk: Buffer) => {
      errorBytes += chunk.byteLength;
      if (errorBytes <= 64 * 1024) errors.push(Buffer.from(chunk));
      else child.kill("SIGKILL");
    });
    stdin.end(input);
    let timedOut = false;
    const deadline = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, 30_000);
    deadline.unref();
    const status = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolveExit, rejectExit) => {
      child.once("error", rejectExit);
      child.once("exit", (code, signal) => resolveExit({ code, signal }));
    }).finally(() => clearTimeout(deadline));
    if (timedOut) throw new HardwareVmChangeSetApplyError("runtime", "change-set runtime exceeded 30 seconds");
    const text = Buffer.concat(output).toString("utf8");
    const response = parseToolResponse(text);
    if (!response.ok) throw new HardwareVmChangeSetApplyError(response.kind, response.message);
    if (status.code !== 0 || status.signal !== null) {
      throw new HardwareVmChangeSetApplyError(
        "runtime",
        `change-set runtime failed (${status.code ?? status.signal ?? "unknown"}): ${Buffer.concat(errors).toString("utf8").slice(-4096)}`,
      );
    }
    return response.report;
  } finally {
    closeSync(runtime);
  }
}

function verifiedRuntimeDescriptor(): { path: string; sha256: string } {
  const registration = hardwareVmExtension();
  const descriptor: unknown = JSON.parse(readFileSync(registration.descriptorPath, "utf8"));
  if (!record(descriptor)) throw new HardwareVmChangeSetApplyError("runtime", "extension descriptor is invalid");
  const runtime = descriptor.runtime;
  if (!record(runtime) || typeof runtime.path !== "string" || typeof runtime.sha256 !== "string") {
    throw new HardwareVmChangeSetApplyError("runtime", "extension runtime descriptor is invalid");
  }
  if (!/^[A-Za-z0-9._-]+$/u.test(runtime.path) || !/^[a-f0-9]{64}$/u.test(runtime.sha256)) {
    throw new HardwareVmChangeSetApplyError("runtime", "extension runtime identity is invalid");
  }
  const path = resolve(dirname(registration.descriptorPath), runtime.path);
  return { path, sha256: runtime.sha256 };
}

function parseToolResponse(text: string):
  | { ok: true; report: HardwareVmApplyReport }
  | { ok: false; kind: HardwareVmChangeSetApplyError["kind"]; message: string } {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new HardwareVmChangeSetApplyError("runtime", "change-set runtime returned invalid output");
  }
  if (!record(value) || typeof value.ok !== "boolean") {
    throw new HardwareVmChangeSetApplyError("runtime", "change-set runtime returned an invalid response");
  }
  if (!value.ok) {
    const kind = value.kind;
    if ((kind !== "conflict" && kind !== "invalid" && kind !== "io") || typeof value.message !== "string") {
      throw new HardwareVmChangeSetApplyError("runtime", "change-set runtime returned an invalid error");
    }
    return { ok: false, kind, message: value.message.slice(0, 4096) };
  }
  const applied = value.applied;
  if (typeof applied !== "number" || !Number.isSafeInteger(applied) || applied < 0 || typeof value.recovered !== "boolean" || typeof value.journalPath !== "string") {
    throw new HardwareVmChangeSetApplyError("runtime", "change-set runtime returned an invalid report");
  }
  return {
    ok: true,
    report: { applied, recovered: value.recovered, journalPath: value.journalPath },
  };
}

function absolutePath(value: string, label: string): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.includes("\0")) {
    throw new TypeError(`${label} must be an absolute path without NUL`);
  }
  return value;
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function descriptorDigestFromManifest(value: unknown, key: string): string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("hardware-VM native manifest is invalid");
  }
  const files = Reflect.get(value, "files");
  if (typeof files !== "object" || files === null || Array.isArray(files)) {
    throw new TypeError("hardware-VM native manifest files are invalid");
  }
  const digest = Reflect.get(files, key);
  if (typeof digest !== "string" || !/^[a-f0-9]{64}$/u.test(digest)) {
    throw new TypeError("hardware-VM descriptor digest is absent or invalid");
  }
  return digest;
}
