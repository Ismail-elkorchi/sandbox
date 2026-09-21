// Internal Sandsurf wire contract. This does not adapt the prepared-process runtime.
import { createHash } from "node:crypto";

export const SANDSURF_HEADER_BYTES = 56;
export const SANDSURF_AUTHENTICATION_BYTES = 32;
export const SANDSURF_MAX_CONTROL_BYTES = 256 * 1024;
export const SANDSURF_MAX_STREAM_BYTES = 64 * 1024;
const MAGIC = Buffer.from("SSF1");

export type SandsurfDigestDomain = "sandbox" | "grant" | "operation" | "receipt" | "output" | "release" | "image" | "checkpoint" | "transfer" | "network" | "secret" | "resource" | "exposure";
export type SandsurfFrameKind = "control" | "data" | "credit" | "end";
const kinds: readonly SandsurfFrameKind[] = ["control", "data", "credit", "end"];

export interface SandsurfFrame {
  readonly kind: SandsurfFrameKind;
  readonly stream: number;
  readonly sequence: number;
  readonly authentication: Uint8Array;
  readonly payload: Uint8Array;
}

export type SandsurfGuestPath = readonly number[];

export function createSandsurfGuestPath(value: string | Uint8Array): SandsurfGuestPath {
  const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
  const result = [...bytes];
  validateSandsurfGuestPath(result);
  return result;
}

export function validateSandsurfGuestPath(value: unknown): asserts value is SandsurfGuestPath {
  if (!Array.isArray(value) || value.length < 1 || value.length > 4096
    || value.some((byte) => typeof byte !== "number" || !Number.isInteger(byte) || byte < 0 || byte > 255)
    || value[0] !== 0x2f || value.includes(0) || (value.length > 1 && value.at(-1) === 0x2f)) {
    throw new Error("invalid Sandsurf guest path bytes");
  }
  const components: number[][] = [[]];
  for (const byte of value.slice(1)) {
    if (byte === 0x2f) components.push([]); else components.at(-1)?.push(byte);
  }
  if (value.length > 1 && components.some((part) => part.length === 0
    || (part.length === 1 && part[0] === 0x2e)
    || (part.length === 2 && part[0] === 0x2e && part[1] === 0x2e))) {
    throw new Error("Sandsurf guest path is not normalized");
  }
}

export function sandsurfGuestPathUtf8(value: SandsurfGuestPath): string | undefined {
  validateSandsurfGuestPath(value);
  try { return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(value)); }
  catch { return undefined; }
}

export interface SandsurfMutation {
  readonly sandboxId: string;
  readonly epoch: number;
  readonly operationId: string;
  readonly grantId: string;
  readonly expectedRevision: number;
  readonly request: SandsurfWorkloadRequest;
  readonly requestDigest: string;
}

export interface SandsurfSpawnRequest {
  readonly sandboxId: string;
  readonly epoch: number;
  readonly processId: string;
  readonly operationId: string;
  readonly argv: readonly string[];
  readonly cwd: string;
  readonly environment: Readonly<Record<string, string>>;
  readonly user: string | null;
  readonly stdio: "pipes" | "terminal";
  readonly terminalSize: SandsurfTerminalSize | null;
  readonly lifetime: "job" | "sandbox";
  readonly deadlineMillis: number | null;
  readonly outputBytes: number;
}

export interface SandsurfTerminalSize {
  readonly columns: number;
  readonly rows: number;
  readonly pixelWidth: number;
  readonly pixelHeight: number;
}

export type SandsurfWorkloadRequest =
  | { readonly kind: "spawn"; readonly request: SandsurfSpawnRequest }
  | { readonly kind: "write-input"; readonly processId: string; readonly terminalLeaseId: string | null; readonly bytes: readonly number[] }
  | { readonly kind: "close-input"; readonly processId: string; readonly terminalLeaseId: string | null }
  | { readonly kind: "acquire-terminal-input"; readonly processId: string; readonly terminalLeaseId: string }
  | { readonly kind: "release-terminal-input"; readonly processId: string; readonly terminalLeaseId: string }
  | { readonly kind: "resize-terminal"; readonly processId: string; readonly size: SandsurfTerminalSize }
  | { readonly kind: "signal"; readonly processId: string; readonly signal: number; readonly group: boolean }
  | { readonly kind: "terminate"; readonly processId: string; readonly graceMillis: number }
  | { readonly kind: "filesystem"; readonly request: Readonly<Record<string, unknown>> };

export interface SandsurfOutputBoundary {
  readonly finalCursor: number;
  readonly chunks: number;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly terminalBytes: number;
  readonly omittedBytes: number;
  readonly finalHash: string;
}

export interface SandsurfReleaseRequest {
  readonly receiptDigest: string;
  readonly output: SandsurfOutputBoundary;
  readonly disposition:
    | { readonly kind: "complete-capture"; readonly commitment: {
      readonly storeId: string; readonly commitmentId: string; readonly manifestDigest: string;
      readonly receiptDigest: string; readonly output: SandsurfOutputBoundary;
    } }
    | { readonly kind: "continuing-retention"; readonly pin: string }
    | { readonly kind: "authorized-loss"; readonly authorization: string };
}

function counter(value: unknown): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) throw new Error("invalid Sandsurf counter");
}
function identity(value: unknown): asserts value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,128}$/u.test(value)) throw new Error("invalid Sandsurf identity");
}
function sha256(value: unknown): asserts value is string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) throw new Error("invalid Sandsurf digest");
}
function record(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("expected Sandsurf record");
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) throw new Error("unknown or missing Sandsurf record fields");
}

export function validateSandsurfMutation(value: unknown): asserts value is SandsurfMutation {
  record(value, ["sandboxId", "epoch", "operationId", "grantId", "expectedRevision", "request", "requestDigest"]);
  identity(value.sandboxId); identity(value.operationId); identity(value.grantId);
  counter(value.epoch); counter(value.expectedRevision); sha256(value.requestDigest);
  if (value.epoch === 0 || value.expectedRevision === 0) throw new Error("Sandsurf mutation epoch and revision must be positive");
  validateWorkloadRequest(value.request);
  if (value.request.kind === "spawn" && (value.request.request.sandboxId !== value.sandboxId
    || value.request.request.epoch !== value.epoch || value.request.request.operationId !== value.operationId)) {
    throw new Error("Sandsurf spawn identity does not match its mutation");
  }
  const expected = sandsurfDigest("operation", ["sandsurf-workload-mutation-v1", value.sandboxId,
    value.epoch, value.operationId, value.grantId, value.expectedRevision, value.request]);
  if (value.requestDigest !== expected) throw new Error("Sandsurf mutation digest mismatch");
}

export function createSandsurfMutation(
  value: Omit<SandsurfMutation, "requestDigest">,
): SandsurfMutation {
  const requestDigest = sandsurfDigest("operation", ["sandsurf-workload-mutation-v1", value.sandboxId,
    value.epoch, value.operationId, value.grantId, value.expectedRevision, value.request]);
  const mutation = { ...value, requestDigest };
  validateSandsurfMutation(mutation);
  return mutation;
}

function validateWorkloadRequest(value: unknown): asserts value is SandsurfWorkloadRequest {
  if (value === null || typeof value !== "object" || !("kind" in value)) throw new Error("missing Sandsurf workload kind");
  const fields = value as Record<string, unknown>;
  switch (fields.kind) {
    case "spawn": record(fields, ["kind", "request"]); validateSpawn(fields.request); break;
    case "write-input":
      record(fields, ["kind", "processId", "terminalLeaseId", "bytes"]); identity(fields.processId);
      if (fields.terminalLeaseId !== null) identity(fields.terminalLeaseId);
      if (!Array.isArray(fields.bytes) || fields.bytes.length < 1 || fields.bytes.length > SANDSURF_MAX_STREAM_BYTES
        || fields.bytes.some((byte) => typeof byte !== "number" || !Number.isInteger(byte) || byte < 0 || byte > 255)) {
        throw new Error("invalid Sandsurf input bytes");
      }
      break;
    case "close-input":
      record(fields, ["kind", "processId", "terminalLeaseId"]); identity(fields.processId);
      if (fields.terminalLeaseId !== null) identity(fields.terminalLeaseId);
      break;
    case "acquire-terminal-input":
    case "release-terminal-input":
      record(fields, ["kind", "processId", "terminalLeaseId"]); identity(fields.processId); identity(fields.terminalLeaseId); break;
    case "resize-terminal": record(fields, ["kind", "processId", "size"]); identity(fields.processId); validateTerminalSize(fields.size); break;
    case "signal":
      record(fields, ["kind", "processId", "signal", "group"]); identity(fields.processId); counter(fields.signal);
      if (fields.signal < 1 || fields.signal > 64 || typeof fields.group !== "boolean") throw new Error("invalid Sandsurf signal");
      break;
    case "terminate":
      record(fields, ["kind", "processId", "graceMillis"]); identity(fields.processId); counter(fields.graceMillis);
      if (fields.graceMillis > 60_000) throw new Error("invalid Sandsurf termination grace");
      break;
    case "filesystem":
      record(fields, ["kind", "request"]);
      if (!recordValue(fields.request) || typeof fields.request.kind !== "string") throw new Error("invalid Sandsurf filesystem request");
      break;
    default: throw new Error("unknown Sandsurf workload request");
  }
}

function recordValue(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateSpawn(value: unknown): asserts value is SandsurfSpawnRequest {
  record(value, ["sandboxId", "epoch", "processId", "operationId", "argv", "cwd", "environment", "user", "stdio", "terminalSize", "lifetime", "deadlineMillis", "outputBytes"]);
  identity(value.sandboxId); identity(value.processId); identity(value.operationId); counter(value.epoch); counter(value.outputBytes);
  if (value.epoch === 0 || value.outputBytes === 0 || !Array.isArray(value.argv) || value.argv.length < 1 || value.argv.length > 4096
    || value.argv.some((item) => typeof item !== "string" || item.length < 1 || item.length > 64 * 1024 || item.includes("\0"))) {
    throw new Error("invalid Sandsurf spawn arguments");
  }
  guestPath(value.cwd);
  if (value.environment === null || typeof value.environment !== "object" || Array.isArray(value.environment)
    || Object.keys(value.environment).length > 4096) throw new Error("invalid Sandsurf environment");
  for (const [name, item] of Object.entries(value.environment)) {
    if (name.length < 1 || name.length > 4096 || name.includes("=") || name.includes("\0")
      || typeof item !== "string" || item.length > 64 * 1024 || item.includes("\0")) throw new Error("invalid Sandsurf environment");
  }
  if (value.user !== null && (typeof value.user !== "string" || value.user.length < 1 || value.user.length > 4096 || value.user.includes("\0"))) {
    throw new Error("invalid Sandsurf workload user");
  }
  if (value.stdio === "terminal") validateTerminalSize(value.terminalSize);
  else if (value.stdio !== "pipes" || value.terminalSize !== null) throw new Error("invalid Sandsurf stdio mode");
  if (value.lifetime !== "job" && value.lifetime !== "sandbox") throw new Error("invalid Sandsurf process lifetime");
  if (value.deadlineMillis !== null) {
    counter(value.deadlineMillis);
    if (value.deadlineMillis === 0 || value.deadlineMillis > 30 * 24 * 60 * 60 * 1000) throw new Error("invalid Sandsurf process deadline");
  }
}

function validateTerminalSize(value: unknown): asserts value is SandsurfTerminalSize {
  record(value, ["columns", "rows", "pixelWidth", "pixelHeight"]);
  for (const name of ["columns", "rows", "pixelWidth", "pixelHeight"] as const) {
    counter(value[name]); if (value[name] > 0xffff) throw new Error("invalid Sandsurf terminal dimension");
  }
  if (value.columns === 0 || value.rows === 0) throw new Error("invalid Sandsurf terminal size");
}

function guestPath(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 4096 || !value.startsWith("/")
    || value.includes("\0") || value.split("/").includes("..")) throw new Error("invalid Sandsurf guest path");
}

export function validateSandsurfOutputBoundary(value: unknown): asserts value is SandsurfOutputBoundary {
  record(value, ["finalCursor", "chunks", "stdoutBytes", "stderrBytes", "terminalBytes", "omittedBytes", "finalHash"]);
  for (const name of ["finalCursor", "chunks", "stdoutBytes", "stderrBytes", "terminalBytes", "omittedBytes"]) counter(value[name]);
  sha256(value.finalHash);
}

export function validateSandsurfRelease(value: unknown): asserts value is SandsurfReleaseRequest {
  record(value, ["receiptDigest", "output", "disposition"]);
  sha256(value.receiptDigest); validateSandsurfOutputBoundary(value.output);
  const disposition = value.disposition;
  if (disposition === null || typeof disposition !== "object" || !("kind" in disposition)) throw new Error("missing release disposition");
  const fields = disposition as Record<string, unknown>;
  switch (fields.kind) {
    case "complete-capture": {
      record(fields, ["kind", "commitment"]);
      const commitment = fields.commitment;
      record(commitment, ["storeId", "commitmentId", "manifestDigest", "receiptDigest", "output"]);
      identity(commitment.storeId); identity(commitment.commitmentId); sha256(commitment.manifestDigest);
      sha256(commitment.receiptDigest); validateSandsurfOutputBoundary(commitment.output);
      break;
    }
    case "continuing-retention": record(fields, ["kind", "pin"]); identity(fields.pin); break;
    case "authorized-loss": record(fields, ["kind", "authorization"]); identity(fields.authorization); break;
    default: throw new Error("unknown release disposition");
  }
  // Coverage, pins and loss decisions are checked by the authority, not this codec.
}

function validateFrame(kind: SandsurfFrameKind, stream: number, sequence: number, length: number): void {
  counter(sequence); counter(stream);
  if (stream > 0xffff_ffff) throw new Error("stream ID overflow");
  const valid = kind === "control" ? stream === 0 && length <= SANDSURF_MAX_CONTROL_BYTES
    : kind === "data" ? stream !== 0 && length >= 1 && length <= SANDSURF_MAX_STREAM_BYTES
    : kind === "credit" ? stream !== 0 && length === 8
    : kind === "end" && stream !== 0 && length === 0;
  if (!valid) throw new Error("invalid Sandsurf frame bounds");
}

export function encodeSandsurfFrame(frame: SandsurfFrame): Buffer {
  validateFrame(frame.kind, frame.stream, frame.sequence, frame.payload.byteLength);
  if (frame.authentication.byteLength !== SANDSURF_AUTHENTICATION_BYTES) throw new Error("invalid Sandsurf frame authentication");
  const header = Buffer.alloc(SANDSURF_HEADER_BYTES);
  MAGIC.copy(header); header.writeUInt16BE(2, 4); header[6] = kinds.indexOf(frame.kind) + 1;
  header.writeUInt32BE(frame.stream, 8); header.writeBigUInt64BE(BigInt(frame.sequence), 12);
  header.writeUInt32BE(frame.payload.byteLength, 20);
  header.set(frame.authentication, 24);
  return Buffer.concat([header, frame.payload]);
}

/** One bounded frame of staging memory, including when the transport fragments every byte. */
export class SandsurfFrameDecoder {
  readonly #header = Buffer.alloc(SANDSURF_HEADER_BYTES);
  #headerUsed = 0;
  #payload: Buffer | undefined;
  #payloadUsed = 0;
  #kind: SandsurfFrameKind = "control";
  #stream = 0;
  #sequence = 0;
  #authentication = Buffer.alloc(SANDSURF_AUTHENTICATION_BYTES);
  #failed = false;

  *push(bytes: Uint8Array): Generator<SandsurfFrame> {
    if (this.#failed) throw new Error("Sandsurf decoder is failed");
    let offset = 0;
    try {
      while (offset < bytes.length) {
        if (this.#payload === undefined) {
          const count = Math.min(SANDSURF_HEADER_BYTES - this.#headerUsed, bytes.length - offset);
          this.#header.set(bytes.subarray(offset, offset + count), this.#headerUsed);
          this.#headerUsed += count; offset += count;
          if (this.#headerUsed < SANDSURF_HEADER_BYTES) continue;
          if (!this.#header.subarray(0, 4).equals(MAGIC) || this.#header.readUInt16BE(4) !== 2 || this.#header[7] !== 0) throw new Error("invalid Sandsurf header");
          const kind = kinds[(this.#header[6] ?? 0) - 1];
          if (kind === undefined) throw new Error("unknown Sandsurf frame kind");
          const stream = this.#header.readUInt32BE(8);
          const sequence = Number(this.#header.readBigUInt64BE(12));
          const length = this.#header.readUInt32BE(20);
          validateFrame(kind, stream, sequence, length);
          this.#kind = kind; this.#stream = stream; this.#sequence = sequence;
          this.#authentication = Buffer.from(this.#header.subarray(24, 56));
          this.#payload = Buffer.alloc(length); // Header bounds checked before allocation.
          this.#payloadUsed = 0;
        }
        const count = Math.min(this.#payload.length - this.#payloadUsed, bytes.length - offset);
        this.#payload.set(bytes.subarray(offset, offset + count), this.#payloadUsed);
        this.#payloadUsed += count; offset += count;
        if (this.#payloadUsed !== this.#payload.length) continue;
        const frame = { kind: this.#kind, stream: this.#stream, sequence: this.#sequence, authentication: this.#authentication, payload: this.#payload };
        this.#headerUsed = 0; this.#payload = undefined; this.#payloadUsed = 0;
        yield frame;
      }
    } catch (error) { this.#failed = true; throw error; }
  }

  finish(): void {
    if (this.#failed || this.#headerUsed !== 0 || this.#payload !== undefined) {
      this.#failed = true;
      throw new Error("incomplete Sandsurf frame");
    }
  }
}

/** Same domain-separated canonical encoding as sandbox-digest's Sandsurf domains. */
export function sandsurfDigest(domain: SandsurfDigestDomain, value: unknown): string {
  if (!["sandbox", "grant", "operation", "receipt", "output", "release", "image", "checkpoint", "transfer", "network", "secret", "resource", "exposure"].includes(domain)) throw new Error("unknown digest domain");
  const hash = createHash("sha256");
  let encodedBytes = 0;
  const put = (bytes: Uint8Array): void => {
    encodedBytes += bytes.length;
    if (encodedBytes > 2 * SANDSURF_MAX_CONTROL_BYTES) throw new Error("canonical digest input too large");
    hash.update(bytes);
  };
  const length = (value: number): void => { const b = Buffer.alloc(4); b.writeUInt32BE(value); put(b); };
  const string = (value: string): void => {
    if (!value.isWellFormed() || value.length > SANDSURF_MAX_CONTROL_BYTES) throw new Error("invalid digest string");
    const bytes = Buffer.from(value); length(bytes.length); put(bytes);
  };
  const visit = (item: unknown, depth: number): void => {
    if (depth > 64) throw new Error("digest nesting too deep");
    if (item === null) { put(Buffer.from([0])); return; }
    if (typeof item === "boolean") { put(Buffer.from([1, Number(item)])); return; }
    if (typeof item === "number") {
      if (!Number.isSafeInteger(item) || Object.is(item, -0)) throw new Error("non-canonical digest number");
      put(Buffer.from([2, item < 0 ? 1 : 0]));
      const b = Buffer.alloc(8); if (item < 0) b.writeBigInt64BE(BigInt(item)); else b.writeBigUInt64BE(BigInt(item)); put(b); return;
    }
    if (typeof item === "string") { put(Buffer.from([3])); string(item); return; }
    if (Array.isArray(item)) { put(Buffer.from([4])); length(item.length); for (const child of item) visit(child, depth + 1); return; }
    if (typeof item === "object" && (Object.getPrototypeOf(item) === Object.prototype || Object.getPrototypeOf(item) === null)) {
      const entries = Object.entries(item).sort(([a], [b]) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
      put(Buffer.from([5])); length(entries.length);
      for (const [key, child] of entries) { string(key); visit(child, depth + 1); }
      return;
    }
    throw new Error("unsupported canonical digest value");
  };
  string("SBX-DIGEST-1"); string(`SANDSURF/${domain.toUpperCase()}/1`); visit(value, 0);
  return hash.digest("hex");
}
