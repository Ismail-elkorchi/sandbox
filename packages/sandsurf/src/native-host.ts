import { createHash } from "node:crypto";
import { sha256File } from "./file-integrity.js";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { lstat, readFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Readable } from "node:stream";

const BRIDGE_VERSION = 1;
const MAX_BRIDGE_BYTES = 1024 * 1024 + 256 * 1024 + 4;
const MAX_BRIDGE_PENDING = 64;
const MAX_OBSERVATION_STREAMS = 8;
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
  readonly #binary: string;
  readonly #streams = new Map<ChildProcessWithoutNullStreams, Promise<void>>();
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
    this.#binary = binary;
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
    // Only the native host may admit or create its private storage root. A
    // client must never chmod an existing directory to make admission succeed.
    const binary = await resolveSandsurfNativeHost();
    const client = new NativeHostClient(directory, binary);
    let opened = false;
    try {
      try {
        await client.request({ kind: "inspect" });
        if (service === "auto") await ensureSupervisor(binary, directory);
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
          await ensureSupervisor(binary, directory);
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
    const bytes = encodeBridgeRequest(id, request);
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
    for (const stream of this.#streams.keys()) stream.kill();
    if (this.#pending.size !== 0) await new Promise<void>((resolveDrain) => { this.#drained.push(resolveDrain); });
    this.#bridge.stdin.end();
    await this.#exited;
    await Promise.all(this.#streams.values());
  }

  async *eventPages(machineId: string, after: number, maximum: number, signal?: AbortSignal): AsyncGenerator<Record<string, unknown>, void> {
    yield* this.#observationPages("events", ["event-stream", "--machine", machineId, "--after", String(after), "--maximum", String(maximum)], signal);
  }

  async *consolePages(machineId: string, generation: number, after: number, maximum: number, signal?: AbortSignal): AsyncGenerator<Record<string, unknown>, void> {
    yield* this.#observationPages("console", ["console-stream", "--machine", machineId, "--generation", String(generation), "--after", String(after), "--maximum", String(maximum)], signal);
  }

  async *#observationPages(kind: "events" | "console", args: readonly string[], signal?: AbortSignal): AsyncGenerator<Record<string, unknown>, void> {
    const aborted = (): boolean => signal?.aborted === true;
    if (this.#closed) throw new SandsurfHostError("client", "Sandsurf client is closed");
    if (this.#failed !== undefined) throw this.#failed;
    if (aborted()) throw signal?.reason;
    if (this.#streams.size >= MAX_OBSERVATION_STREAMS) throw new SandsurfHostError("capacity", "native observation stream capacity is full");
    const child = spawn(this.#binary, [...args, "--directory", this.directory], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    let errorText = "";
    let failure: Error | undefined;
    child.stderr.on("data", (chunk: Buffer) => { errorText = (errorText + chunk.toString("utf8")).slice(-4096); });
    child.on("error", (error: Error) => { failure = error; });
    child.stdin.on("error", (error: Error) => { failure = error; child.kill(); });
    const exited = new Promise<void>((done) => { child.once("close", () => done()); });
    this.#streams.set(child, exited);
    const abort = (): void => { child.kill(); };
    signal?.addEventListener("abort", abort, { once: true });
    try {
      for await (const frame of bridgeFrames(child.stdout)) {
        if (aborted()) throw signal?.reason;
        const [id, value] = decodeBridgeFrame(frame);
        if (value.kind === "rejected") throw new SandsurfHostError(text(value.category), text(value.message));
        if (id !== 1 || value.kind !== "runtime" || !record(value.response) || value.response.kind !== kind || !record(value.response.page)) throw new SandsurfHostError("protocol", "invalid native observation stream page");
        const cursor = integer(value.response.page.cursor);
        yield value;
        if (this.#closed) return;
        if (aborted()) throw signal?.reason;
        const credit = Buffer.alloc(8); credit.writeBigUInt64LE(BigInt(cursor));
        await new Promise<void>((done, reject) => child.stdin.write(credit, (error?: Error | null) => error == null ? done() : reject(error)));
      }
      if (aborted()) throw signal?.reason;
      if (!this.#closed) throw new SandsurfHostError("transport", `native observation stream ended: ${failure?.message ?? errorText}`);
    } catch (error) {
      if (aborted()) throw signal?.reason;
      if (!this.#closed) throw error instanceof SandsurfHostError ? error : new SandsurfHostError("transport", `native observation stream failed: ${String(error)}`);
    } finally {
      signal?.removeEventListener("abort", abort);
      child.kill();
      child.stdin.destroy();
      await exited;
      this.#streams.delete(child);
    }
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
      this.#buffer = Buffer.alloc(0);
      let id: number;
      let value: Record<string, unknown>;
      try { [id, value] = decodeBridgeFrame(frame); }
      catch (error) {
        this.#fail(error instanceof SandsurfHostError ? error : new SandsurfHostError("protocol", "native bridge returned invalid binary output"));
        return;
      }
      const pending = this.#pending.get(id);
      if (pending === undefined) { this.#fail(new SandsurfHostError("protocol", "native bridge returned an unknown request identity")); return; }
      this.#pending.delete(id);
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
    for (const stream of this.#streams.keys()) stream.kill();
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

  /** Explicit administrative containment of supervisor-owned guardians. */
  async stopSupervisor(): Promise<void> {
    if (await supervisorCommand(this.#binary, "stop-supervisor", this.directory) !== 0) {
      throw new SandsurfHostError("supervision", "guardian supervisor did not confirm shutdown");
    }
  }
}

// The SDK caller bootstraps this owner, never the host API process. Installed
// service definitions use two independent native services for the same roles.
async function ensureSupervisor(binary: string, directory: string): Promise<void> {
  const status = await supervisorCommand(binary, "supervisor-status", directory);
  if (status === 0) return;
  if (status !== 2) throw new SandsurfHostError("supervision", "existing guardian supervisor is unhealthy; refusing a second owner");
  const child = spawn(binary, ["supervise", "--directory", directory], { detached: true, stdio: "ignore", windowsHide: true });
  let launchError: Error | undefined;
  child.once("error", (error: Error) => { launchError = error; });
  child.unref();
  const deadline = Date.now() + 10_000;
  do {
    if (launchError !== undefined) throw new SandsurfHostError("supervision", `guardian supervisor could not start: ${launchError.message}`);
    const observed = await supervisorCommand(binary, "supervisor-status", directory);
    if (observed === 0) return;
    if (observed !== 2) throw new SandsurfHostError("supervision", "guardian supervisor endpoint is incompatible or unhealthy");
    await new Promise((done) => setTimeout(done, 20));
  } while (Date.now() < deadline);
  throw new SandsurfHostError("supervision", "guardian supervisor did not become reachable");
}

function supervisorCommand(binary: string, mode: "supervisor-status" | "stop-supervisor", directory: string): Promise<number | null> {
  return new Promise((done, reject) => {
    const child = spawn(binary, [mode, "--directory", directory], { stdio: "ignore", windowsHide: true });
    child.once("error", reject);
    child.once("exit", (code) => done(code));
  });
}

async function* bridgeFrames(output: Readable): AsyncGenerator<Buffer, void> {
  let buffered = Buffer.alloc(0);
  for await (const chunk of output) {
    const bytes = Buffer.from(chunk as Uint8Array);
    let position = 0;
    while (position < bytes.byteLength) {
      const target = buffered.byteLength < 4 ? 4 : 4 + buffered.readUInt32LE(0);
      const take = Math.min(target - buffered.byteLength, bytes.byteLength - position);
      buffered = Buffer.concat([buffered, bytes.subarray(position, position + take)]);
      position += take;
      if (buffered.byteLength === 4 && (buffered.readUInt32LE(0) === 0 || buffered.readUInt32LE(0) > MAX_BRIDGE_BYTES)) throw new SandsurfHostError("protocol", "native stream frame exceeds its byte bound");
      if (buffered.byteLength >= 4 && buffered.byteLength === 4 + buffered.readUInt32LE(0)) {
        yield buffered.subarray(4);
        buffered = Buffer.alloc(0);
      }
    }
  }
  if (buffered.byteLength !== 0) throw new SandsurfHostError("protocol", "native stream ended inside a frame");
}

function decodeBridgeFrame(frame: Buffer): [number, Record<string, unknown>] {
  if (frame.byteLength < 4) throw new SandsurfHostError("protocol", "native bridge returned a truncated envelope");
  const jsonLength = frame.readUInt32LE(0);
  if (jsonLength === 0 || jsonLength > 256 * 1024 || jsonLength > frame.byteLength - 4) throw new SandsurfHostError("protocol", "native bridge returned an invalid envelope length");
  let parsed: unknown;
  try { parsed = JSON.parse(frame.subarray(4, 4 + jsonLength).toString("utf8")); }
  catch { throw new SandsurfHostError("protocol", "native bridge returned invalid JSON"); }
  if (!Array.isArray(parsed) || parsed.length !== 3 || !Number.isSafeInteger(parsed[0]) || parsed[0] <= 0 || parsed[1] !== BRIDGE_VERSION || !record(parsed[2])) throw new SandsurfHostError("protocol", "native host returned an invalid response");
  return [parsed[0], decodeBridgeResponse(parsed[2], frame.subarray(4 + jsonLength))];
}

function encodeBridgeRequest(id: number, request: Readonly<Record<string, unknown>>): Buffer {
  let path: string[] | undefined; let maximum = 64 * 1024;
  const guestRequest = (value: Readonly<Record<string, unknown>>, prefix: string[]): void => {
    if (value.kind === "write-input") path = [...prefix, "bytes"];
    if (value.kind === "filesystem" && record(value.request)) filesystem(value.request, [...prefix, "request"]);
  };
  const filesystem = (value: Readonly<Record<string, unknown>>, prefix: string[]): void => {
    if (value.kind === "write" || value.kind === "write-chunk") path = [...prefix, "bytes"];
  };
  if (request.kind === "put-secret") { path = ["bytes"]; maximum = 1024 * 1024; }
  else if (request.kind === "write-console") { path = ["bytes"]; maximum = 4096; }
  else if (request.kind === "dispatch-guest" && record(request.request)) guestRequest(request.request, ["request"]);
  else if (request.kind === "guest" && record(request.request)) {
    const value = request.request;
    if (value.kind === "filesystem-query" && record(value.request)) filesystem(value.request, ["request", "request"]);
  }
  let wire: Record<string, unknown> = { ...request }; let data = Buffer.alloc(0);
  let binary: { length: number; digest: string }[] | null = null;
  if (path !== undefined) {
    let source: Readonly<Record<string, unknown>> = request; let target = wire;
    for (const key of path.slice(0, -1)) {
      const child = source[key];
      if (!record(child)) throw new SandsurfHostError("protocol", "invalid request byte path");
      const copy = { ...child }; target[key] = copy; target = copy; source = child;
    }
    const key = path.at(-1)!; const field = source[key];
    if (!(field instanceof Uint8Array) && (!Array.isArray(field) || !field.every((value: unknown) => Number.isInteger(value) && (value as number) >= 0 && (value as number) <= 255))) throw new SandsurfHostError("protocol", "invalid request bytes");
    data = Buffer.from(field as Uint8Array);
    if (data.byteLength > maximum) throw new SandsurfHostError("capacity", "request bytes exceed their bound");
    target[key] = []; binary = [];
    for (let offset = 0; offset < data.byteLength; offset += 64 * 1024) {
      const chunk = data.subarray(offset, offset + 64 * 1024);
      binary.push({ length: chunk.byteLength, digest: createHash("sha256").update(chunk).digest("hex") });
    }
  }
  const json = Buffer.from(JSON.stringify([id, BRIDGE_VERSION, { request: wire, binary }]), "utf8");
  if (json.byteLength > 256 * 1024) throw new SandsurfHostError("protocol", "request metadata exceeds its bound");
  const header = Buffer.allocUnsafe(4); header.writeUInt32LE(json.byteLength);
  return Buffer.concat([header, json, data]);
}

function decodeBridgeResponse(value: Record<string, unknown>, binary: Buffer): Record<string, unknown> {
  const decodeChunks = (entries: unknown): Buffer[] => {
    if (!Array.isArray(entries) || entries.length > 256 || binary.byteLength > 1024 * 1024) throw new SandsurfHostError("protocol", "invalid binary descriptor");
    let position = 0;
    const chunks = entries.map((entry: unknown) => {
      if (!record(entry)) throw new SandsurfHostError("protocol", "invalid binary chunk");
      const length = integer(entry.length);
      if (length < 1 || length > 64 * 1024 || position + length > binary.byteLength) throw new SandsurfHostError("protocol", "invalid binary chunk length");
      const bytes = binary.subarray(position, position + length); position += length;
      if (createHash("sha256").update(bytes).digest("hex") !== text(entry.digest)) throw new SandsurfHostError("integrity", "binary chunk failed digest verification");
      return bytes;
    });
    if (position !== binary.byteLength) throw new SandsurfHostError("protocol", "binary coverage is incomplete");
    return chunks;
  };
  if (value.kind === "host-blob-metadata") {
    const bytes = Buffer.concat(decodeChunks(value.chunks));
    if (bytes.byteLength > 64 * 1024 || typeof value.eof !== "boolean") throw new SandsurfHostError("protocol", "invalid blob range");
    return { kind: "host-blob", offset: integer(value.offset), eof: value.eof, digest: text(value.digest), bytes };
  }
  if (value.kind === "guest" && record(value.response)) {
    const response = value.response;
    if (response.kind === "file" && record(response.response) && response.response.kind === "read-metadata" && record(response.response.range)) {
      const range = response.response.range;
      const bytes = Buffer.concat(decodeChunks(range.chunks));
      if (!record(range.observation)) throw new SandsurfHostError("protocol", "invalid file observation");
      const offset = integer(range.offset); const size = integer(range.observation.size);
      text(range.observation.token);
      if (bytes.byteLength > 64 * 1024 || offset + bytes.byteLength > size || range.eof !== (offset + bytes.byteLength === size) || (bytes.byteLength === 0 && !range.eof)) throw new SandsurfHostError("protocol", "invalid file range coverage");
      return { kind: "guest", response: { kind: "file", response: { kind: "read", range: { offset, eof: range.eof, observation: range.observation, bytes } } } };
    }
    if (response.kind === "output-metadata" && record(response.page)) {
      const page = response.page;
      const entries = page.chunks;
      const bytes = decodeChunks(entries);
      const after = integer(page.after); const available = integer(page.available); let cursor = after;
      if (after > available || binary.byteLength > 64 * 1024 || (!Array.isArray(entries)) || (entries.length !== 0 && page.requiredBytes !== null)) throw new SandsurfHostError("protocol", "invalid guest output boundary");
      const chunks = entries.map((entry: unknown, index: number) => {
        if (!record(entry) || integer(entry.cursor) !== cursor) throw new SandsurfHostError("protocol", "invalid guest output cursor");
        cursor += bytes[index]!.byteLength;
        return { ...entry, bytes: bytes[index]! };
      });
      if (cursor > available) throw new SandsurfHostError("protocol", "invalid guest output coverage");
      return { kind: "guest", response: { kind: "output", page: { ...page, chunks } } };
    }
    if (response.kind === "output" || (response.kind === "file" && record(response.response) && response.response.kind === "read")) throw new SandsurfHostError("protocol", "RPC bytes must use binary data");
  }
  if (value.kind === "runtime" && record(value.response) && value.response.kind === "console-metadata") {
    const page = value.response.page;
    if (!record(page)) throw new SandsurfHostError("protocol", "invalid native console metadata");
    const length = integer(page.length); const after = integer(page.after); const cursor = integer(page.cursor);
    const available = integer(page.available); const generation = integer(page.generation);
    if (generation < 1 || length > 64 * 1024 || length !== binary.byteLength || after > cursor || cursor > available ||
        typeof page.open !== "boolean" || typeof page.captureFailed !== "boolean" ||
        createHash("sha256").update(binary).digest("hex") !== text(page.digest)) throw new SandsurfHostError("protocol", "invalid native console boundary");
    if (page.loss === null) {
      if (after + length !== cursor) throw new SandsurfHostError("protocol", "incomplete native console coverage");
    } else if (!record(page.loss) || integer(page.loss.from) !== after + length || integer(page.loss.to) !== cursor || cursor <= after + length) {
      throw new SandsurfHostError("protocol", "invalid native console loss coverage");
    }
    return { kind: "runtime", response: { kind: "console", page: { ...page, bytes: binary } } };
  }
  if (value.kind !== "runtime" || !record(value.response) || value.response.kind !== "output-metadata") {
    if (binary.byteLength !== 0 || value.kind === "host-blob" || (value.kind === "runtime" && record(value.response) && (value.response.kind === "output" || value.response.kind === "console"))) throw new SandsurfHostError("protocol", "unexpected native bridge data");
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
  if (!record(manifest) || manifest.formatVersion !== 1 || manifest.buildId !== "sandsurf-native-1.0.0"
    || !record(manifest.files) || Object.keys(manifest).sort().join(",") !== "buildId,files,formatVersion") {
    throw new SandsurfHostError("integrity", "native manifest is malformed");
  }
  const expected = manifest.files[relative];
  if (typeof expected !== "string" || !/^[a-f0-9]{64}$/u.test(expected)) {
    throw new SandsurfHostError("unsupported", `native Sandsurf host is not packaged for ${platform}-${architecture}`);
  }
  const binary = resolve(packageRoot, "native", relative);
  const metadata = await lstat(binary);
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new SandsurfHostError("integrity", "native host is not a regular file");
  const actual = await sha256File(binary, 512 * 1024 ** 2);
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
