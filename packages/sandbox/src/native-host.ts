import { createHash } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmod, lstat, mkdir, readFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const BRIDGE_VERSION = 2;
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
  #pending = new Map<number, { resolve: (value: Record<string, unknown>) => void; reject: (error: Error) => void }>();
  #drained: (() => void)[] = [];
  #nextId = 1;
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
    if (this.#failed !== undefined) throw this.#failed;
    if (this.#nextId > Number.MAX_SAFE_INTEGER) throw new SandsurfHostError("capacity", "native bridge request identity exhausted");
    const id = this.#nextId++;
    const bytes = Buffer.from(JSON.stringify([id, BRIDGE_VERSION, request]), "utf8");
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_BRIDGE_BYTES) throw new SandsurfHostError("protocol", "native bridge request exceeds its byte bound");
    if (this.#pending.size >= MAX_BRIDGE_PENDING) throw new SandsurfHostError("capacity", "native bridge request queue is full");
    return new Promise((resolveRequest, rejectRequest) => {
      this.#pending.set(id, { resolve: resolveRequest, reject: rejectRequest });
      const header = Buffer.allocUnsafe(4); header.writeUInt32LE(bytes.byteLength);
      this.#bridge.stdin.write(Buffer.concat([header, bytes]), (error?: Error | null) => {
        if (error !== undefined && error !== null) this.#fail(new SandsurfHostError("transport", `native bridge write failed: ${error.message}`));
      });
    });
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#pending.size !== 0) await new Promise<void>((resolveDrain) => { this.#drained.push(resolveDrain); });
    this.#bridge.stdin.end();
    await this.#exited;
  }

  #read(chunk: Buffer): void {
    let position = 0;
    while (position < chunk.byteLength) {
      const target = this.#buffer.byteLength < 4 ? 4 : 4 + this.#buffer.readUInt32LE(0);
      const take = Math.min(target - this.#buffer.byteLength, chunk.byteLength - position);
      this.#buffer = Buffer.concat([this.#buffer, chunk.subarray(position, position + take)]);
      position += take;
      if (this.#buffer.byteLength === 4) {
        const length = this.#buffer.readUInt32LE(0);
        if (length === 0 || length > MAX_BRIDGE_BYTES) {
          this.#fail(new SandsurfHostError("protocol", "native bridge returned an invalid frame"));
          return;
        }
      }
      if (this.#buffer.byteLength < 4 || this.#buffer.byteLength < 4 + this.#buffer.readUInt32LE(0)) continue;
      const frame = this.#buffer.subarray(4);
      if (frame.byteLength < 4) {
        this.#fail(new SandsurfHostError("protocol", "native bridge returned a truncated envelope"));
        return;
      }
      const jsonLength = frame.readUInt32LE(0);
      if (jsonLength === 0 || jsonLength > frame.byteLength - 4) {
        this.#fail(new SandsurfHostError("protocol", "native bridge returned an invalid envelope length"));
        return;
      }
      let parsed: unknown;
      try { parsed = JSON.parse(frame.subarray(4, 4 + jsonLength).toString("utf8")); }
      catch { this.#fail(new SandsurfHostError("protocol", "native bridge returned invalid JSON")); return; }
      const binary = frame.subarray(4 + jsonLength);
      this.#buffer = Buffer.alloc(0);
      if (!Array.isArray(parsed) || parsed.length !== 3 || !Number.isSafeInteger(parsed[0]) || parsed[0] <= 0 || parsed[1] !== BRIDGE_VERSION || !record(parsed[2])) {
        this.#fail(new SandsurfHostError("protocol", "native host returned an invalid response"));
        return;
      }
      const pending = this.#pending.get(parsed[0]);
      if (pending === undefined) { this.#fail(new SandsurfHostError("protocol", "native bridge returned an unknown request identity")); return; }
      this.#pending.delete(parsed[0]);
      let value: Record<string, unknown>;
      try { value = decodeBridgeResponse(parsed[2], binary); }
      catch (error) {
        this.#fail(error instanceof SandsurfHostError ? error : new SandsurfHostError("protocol", "native bridge returned invalid binary output"));
        return;
      }
      try {
        if (value.kind === "rejected") pending.reject(new SandsurfHostError(text(value.category), text(value.message)));
        else pending.resolve(value);
      } catch {
        const error = new SandsurfHostError("protocol", "native bridge returned an invalid rejection");
        pending.reject(error);
        this.#fail(error);
        return;
      }
      this.#notifyDrained();
    }
  }

  #fail(error: SandsurfHostError): void {
    if (this.#failed !== undefined) return;
    this.#failed = error;
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
    this.#notifyDrained();
    this.#bridge.kill();
  }

  #notifyDrained(): void {
    if (this.#pending.size === 0) for (const resolveDrain of this.#drained.splice(0)) resolveDrain();
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

function decodeBridgeResponse(value: Record<string, unknown>, binary: Buffer): Record<string, unknown> {
  if (value.kind !== "runtime" || !record(value.response) || value.response.kind !== "output-metadata") {
    if (binary.byteLength !== 0) throw new SandsurfHostError("protocol", "unexpected native bridge data");
    return value;
  }
  const response = value.response;
  if (!record(response.page)) throw new SandsurfHostError("protocol", "invalid output metadata");
  const page = response.page;
  if (!Array.isArray(page.chunks)) throw new SandsurfHostError("protocol", "invalid output metadata");
  const entries = page.chunks as unknown[];
  const after = integer(page.after); const cursor = integer(page.cursor); const available = integer(page.available);
  if (after > cursor || cursor > available || binary.byteLength > 256 * 1024) throw new SandsurfHostError("protocol", "invalid output page boundary");
  let position = 0; let offset = after;
  const chunks = entries.map((entry: unknown) => {
    if (!record(entry)) throw new SandsurfHostError("protocol", "invalid output chunk metadata");
    const length = integer(entry.length);
    if (length < 1 || length > 64 * 1024 || integer(entry.offset) !== offset || position + length > binary.byteLength) {
      throw new SandsurfHostError("protocol", "invalid output chunk boundary");
    }
    const bytes = binary.subarray(position, position + length);
    if (createHash("sha256").update(bytes).digest("hex") !== text(entry.bytesDigest)) {
      throw new SandsurfHostError("integrity", "native output chunk failed digest verification");
    }
    position += length; offset += length;
    return { ...entry, bytes };
  });
  if (position !== binary.byteLength || offset !== cursor) throw new SandsurfHostError("protocol", "native output page coverage is incomplete");
  return { kind: "runtime", response: { kind: "output", page: { ...page, chunks } } };
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
