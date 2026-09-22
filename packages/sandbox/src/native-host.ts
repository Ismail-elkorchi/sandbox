import { createHash } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmod, lstat, mkdir, readFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const API_VERSION = 3;
const MAX_BRIDGE_BYTES = 1024 * 1024;
const MAX_BRIDGE_PENDING = 64;
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
  readonly #bridge: ChildProcessWithoutNullStreams;
  readonly #exited: Promise<void>;
  #finishExit!: () => void;
  #buffer = Buffer.alloc(0);
  #inFlight: { resolve: (value: string) => void; reject: (error: Error) => void } | undefined;
  #queue: Promise<void> = Promise.resolve();
  #queued = 0;
  #failed: SandsurfHostError | undefined;
  #closed = false;

  private constructor(directory: string, binary: string) {
    this.directory = directory;
    this.#exited = new Promise((resolveExit) => { this.#finishExit = resolveExit; });
    this.#bridge = spawn(binary, ["bridge", "--directory", directory], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    let errorText = "";
    this.#bridge.stderr.on("data", (chunk: Buffer) => { errorText = (errorText + chunk.toString("utf8")).slice(-4096); });
    this.#bridge.stdin.on("error", (error: Error) => this.#fail(new SandsurfHostError("transport", `native bridge input failed: ${error.message}`)));
    this.#bridge.stdout.on("error", (error: Error) => this.#fail(new SandsurfHostError("transport", `native bridge output failed: ${error.message}`)));
    this.#bridge.stdout.on("data", (chunk: Buffer) => this.#read(chunk));
    this.#bridge.once("error", (error: Error) => this.#fail(new SandsurfHostError("transport", `native bridge failed: ${error.message}`)));
    this.#bridge.once("exit", (code, signal) => {
      this.#fail(new SandsurfHostError("transport", `native bridge exited (${code ?? signal ?? "unknown"}): ${errorText}`));
      this.#finishExit();
    });
  }

  static async open(directory: string, service: "auto" | "connect" = "auto"): Promise<NativeHostClient> {
    if (!isAbsolute(directory)) throw new TypeError("Sandsurf state directory must be absolute");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") await chmod(directory, 0o700);
    const binary = await resolveSandsurfNativeHost();
    const client = new NativeHostClient(directory, binary);
    let opened = false;
    try {
      try {
        await client.request({ kind: "inspect" });
        opened = true;
        return client;
      } catch (error) {
        if (service === "connect" || !(error instanceof SandsurfHostError) || error.category !== "unavailable") throw error;
      }
      const child = spawn(binary, ["serve", "--directory", directory], { detached: true, stdio: "ignore", windowsHide: true });
      let launchError: Error | undefined;
      child.once("error", (error: Error) => { launchError = error; });
      child.unref();
      const deadline = Date.now() + 10_000;
      let last: unknown;
      do {
        if (launchError !== undefined) throw new SandsurfHostError("transport", `Sandsurf host could not start: ${launchError.message}`);
        try {
          await client.request({ kind: "inspect" });
          opened = true;
          return client;
        } catch (error) {
          if (!(error instanceof SandsurfHostError) || error.category !== "unavailable") throw error;
          last = error;
          await new Promise((done) => setTimeout(done, 20));
        }
      } while (Date.now() < deadline);
      throw new SandsurfHostError("transport", `Sandsurf host did not become reachable: ${String(last)}`);
    } finally {
      if (!opened) await client.close();
    }
  }

  async request(request: Readonly<Record<string, unknown>>): Promise<Record<string, unknown>> {
    if (this.#closed) throw new SandsurfHostError("client", "Sandsurf client is closed");
    const bytes = Buffer.from(JSON.stringify([API_VERSION, request]), "utf8");
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_BRIDGE_BYTES) throw new SandsurfHostError("protocol", "native bridge request exceeds its byte bound");
    if (this.#queued >= MAX_BRIDGE_PENDING) throw new SandsurfHostError("capacity", "native bridge request queue is full");
    this.#queued += 1;
    const task = this.#queue.then(() => this.#exchange(bytes));
    this.#queue = task.then(() => undefined, () => undefined).finally(() => { this.#queued -= 1; });
    const response = await task;
    const parsed: unknown = JSON.parse(response);
    if (!Array.isArray(parsed) || parsed.length !== 2 || parsed[0] !== API_VERSION || !record(parsed[1])) {
      throw new SandsurfHostError("protocol", "native host returned an invalid response");
    }
    const value = parsed[1];
    if (value.kind === "rejected") throw new SandsurfHostError(text(value.category), text(value.message));
    return value;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.#queue;
    this.#bridge.stdin.end();
    await this.#exited;
  }

  #exchange(bytes: Buffer): Promise<string> {
    if (this.#failed !== undefined) return Promise.reject(this.#failed);
    if (this.#inFlight !== undefined) return Promise.reject(new SandsurfHostError("protocol", "native bridge request overlap"));
    return new Promise((resolveExchange, rejectExchange) => {
      this.#inFlight = { resolve: resolveExchange, reject: rejectExchange };
      const header = Buffer.allocUnsafe(4); header.writeUInt32LE(bytes.byteLength);
      this.#bridge.stdin.write(Buffer.concat([header, bytes]), (error?: Error | null) => {
        if (error !== undefined && error !== null) this.#fail(new SandsurfHostError("transport", `native bridge write failed: ${error.message}`));
      });
    });
  }

  #read(chunk: Buffer): void {
    if (this.#buffer.byteLength + chunk.byteLength > MAX_BRIDGE_BYTES + 4) {
      this.#fail(new SandsurfHostError("protocol", "native bridge response exceeds its byte bound"));
      return;
    }
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    if (this.#buffer.byteLength < 4) return;
    const length = this.#buffer.readUInt32LE(0);
    if (length === 0 || length > MAX_BRIDGE_BYTES || this.#buffer.byteLength > length + 4) {
      this.#fail(new SandsurfHostError("protocol", "native bridge returned an invalid frame"));
      return;
    }
    if (this.#buffer.byteLength < length + 4) return;
    const response = this.#buffer.subarray(4).toString("utf8");
    this.#buffer = Buffer.alloc(0);
    const pending = this.#inFlight;
    this.#inFlight = undefined;
    if (pending === undefined) this.#fail(new SandsurfHostError("protocol", "native bridge returned an unsolicited response"));
    else pending.resolve(response);
  }

  #fail(error: SandsurfHostError): void {
    if (this.#failed !== undefined) return;
    this.#failed = error;
    this.#inFlight?.reject(error);
    this.#inFlight = undefined;
    this.#bridge.kill();
  }

  async stopService(): Promise<void> {
    try {
      const response = await this.request({ kind: "stop-service" });
      if (response.kind !== "complete") throw new SandsurfHostError("protocol", "native host did not confirm service stop");
    } finally {
      await this.close();
    }
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
