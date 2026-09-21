import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { chmod, lstat, mkdir, readFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const API_VERSION = 1;
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export class SandsurfHostError extends Error {
  readonly category: string;
  constructor(category: string, message: string) {
    super(message);
    this.name = "SandsurfHostError";
    this.category = category;
  }
}

export class NativeHostClient {
  readonly directory: string;
  readonly #binary: string;

  private constructor(directory: string, binary: string) {
    this.directory = directory;
    this.#binary = binary;
  }

  static async open(directory: string): Promise<NativeHostClient> {
    if (!isAbsolute(directory)) throw new TypeError("Sandsurf state directory must be absolute");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") await chmod(directory, 0o700);
    const binary = await resolveSandsurfNativeHost();
    const client = new NativeHostClient(directory, binary);
    try {
      await client.request({ kind: "inspect" });
      return client;
    } catch {
      const child = spawn(binary, ["serve", "--directory", directory], {
        detached: true,
        stdio: "ignore",
        windowsHide: true,
      });
      child.unref();
    }
    const deadline = Date.now() + 10_000;
    let last: unknown;
    do {
      try {
        await client.request({ kind: "inspect" });
        return client;
      } catch (error) {
        last = error;
        await new Promise((done) => setTimeout(done, 20));
      }
    } while (Date.now() < deadline);
    throw new SandsurfHostError("transport", `Sandsurf host did not become reachable: ${String(last)}`);
  }

  async request(request: Readonly<Record<string, unknown>>): Promise<Record<string, unknown>> {
    const response = await invoke(this.#binary, ["request", "--directory", this.directory], JSON.stringify([API_VERSION, request]));
    const parsed: unknown = JSON.parse(response);
    if (!Array.isArray(parsed) || parsed.length !== 2 || parsed[0] !== API_VERSION || !record(parsed[1])) {
      throw new SandsurfHostError("protocol", "native host returned an invalid response");
    }
    const value = parsed[1];
    if (value.kind === "rejected") throw new SandsurfHostError(text(value.category), text(value.message));
    return value;
  }

  async stopService(): Promise<void> {
    const response = await this.request({ kind: "stop-service" });
    if (response.kind !== "complete") throw new SandsurfHostError("protocol", "native host did not confirm service stop");
  }
}

export async function resolveSandsurfNativeHost(): Promise<string> {
  const platform = process.platform === "darwin" ? "macos" : process.platform === "win32" ? "windows" : process.platform;
  const architecture = process.arch === "x64" ? "x64" : process.arch === "arm64" ? "arm64" : process.arch;
  if (!["linux", "macos", "windows"].includes(platform) || !["x64", "arm64"].includes(architecture)) {
    throw new SandsurfHostError("unsupported", `Sandsurf does not support ${process.platform}-${process.arch}`);
  }
  const suffix = platform === "windows" ? ".exe" : "";
  const relative = `${platform}-${architecture}/sandsurf-host-${platform}-${architecture}${suffix}`;
  const manifest: unknown = JSON.parse(await readFile(resolve(packageRoot, "native/manifest.json"), "utf8"));
  if (!record(manifest) || !record(manifest.files)) throw new SandsurfHostError("integrity", "native manifest is malformed");
  const expected = manifest.files[relative];
  if (typeof expected !== "string" || !/^[a-f0-9]{64}$/u.test(expected)) {
    throw new SandsurfHostError("unsupported", `native Sandsurf host is not packaged for ${platform}-${architecture}`);
  }
  const binary = resolve(packageRoot, "native", relative);
  const metadata = await lstat(binary);
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new SandsurfHostError("integrity", "native host is not a regular file");
  const actual = createHash("sha256").update(await readFile(binary)).digest("hex");
  if (actual !== expected) throw new SandsurfHostError("integrity", "native host failed integrity verification");
  return binary;
}

function invoke(binary: string, arguments_: readonly string[], input: string): Promise<string> {
  return new Promise((resolveInvoke, rejectInvoke) => {
    const output: Buffer[] = [];
    const errors: Buffer[] = [];
    const child = spawn(binary, arguments_, { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    child.stdout.on("data", (chunk: Buffer) => output.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => errors.push(chunk));
    child.once("error", rejectInvoke);
    child.once("exit", (code, signal) => {
      if (code === 0) resolveInvoke(Buffer.concat(output).toString("utf8"));
      else rejectInvoke(new SandsurfHostError("transport", `native host request failed (${code ?? signal ?? "unknown"}): ${Buffer.concat(errors).toString("utf8").slice(-4096)}`));
    });
    child.stdin.end(input);
  });
}

export function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function text(value: unknown): string {
  if (typeof value !== "string") throw new SandsurfHostError("protocol", "native host string field is invalid");
  return value;
}

export function integer(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new SandsurfHostError("protocol", "native host counter field is invalid");
  return value;
}
