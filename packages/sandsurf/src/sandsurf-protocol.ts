// Wire codecs and semantic checks over the source-generated Rust contracts.
import { createHash } from "node:crypto";
import { validateProtocol } from "./protocol-validation.js";
import { SANDSURF_HEADER_BYTES, SANDSURF_AUTHENTICATION_BYTES, SANDSURF_MAX_CONTROL_BYTES, SANDSURF_MAX_STREAM_BYTES, SANDSURF_PROTOCOL_VERSION, SANDSURF_FRAME_MAGIC } from "./protocol-generated.js";
export { SANDSURF_HEADER_BYTES, SANDSURF_AUTHENTICATION_BYTES, SANDSURF_MAX_CONTROL_BYTES, SANDSURF_MAX_STREAM_BYTES } from "./protocol-generated.js";
import type { GuestCommand as SandsurfGuestCommand, GuestRequest as SandsurfGuestRequest, SpawnRequest as ExecutionRequest, TerminalSize as SandsurfTerminalSize, OutputBoundary, ReleaseRequest as SandsurfReleaseRequest } from "./protocol-generated.js";
export type { GuestCommand as SandsurfGuestCommand, GuestRequest as SandsurfGuestRequest, SpawnRequest as ExecutionRequest, TerminalSize as SandsurfTerminalSize, OutputBoundary, ReleaseRequest as SandsurfReleaseRequest } from "./protocol-generated.js";

const MAGIC = Buffer.from(SANDSURF_FRAME_MAGIC);

export type SandsurfDigestDomain = "machine" | "authority" | "operation" | "receipt" | "output" | "release" | "image" | "snapshot" | "transfer" | "network" | "secret" | "resource" | "exposure";
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
    || value[0] !== 0x2f || value.includes(0)) {
    throw new Error("invalid Sandsurf guest path bytes");
  }
}

export function sandsurfGuestPathUtf8(value: SandsurfGuestPath): string | undefined {
  validateSandsurfGuestPath(value);
  try { return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(value)); }
  catch { return undefined; }
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
export function validateSandsurfGuestCommand(value: unknown): asserts value is SandsurfGuestCommand {
  validateProtocol("GuestCommand", value);
  identity(value.machineId); identity(value.operationId);
  counter(value.generation); sha256(value.requestDigest);
  if (value.generation === 0) throw new Error("Sandsurf command generation must be positive");
  validateGuestRequest(value.request);
  if (value.request.kind === "spawn" && (value.request.request.machineId !== value.machineId
    || value.request.request.generation !== value.generation || value.request.request.operationId !== value.operationId)) {
    throw new Error("Sandsurf spawn identity does not match its command");
  }
  const expected = guestCommandDigest({ machineId: value.machineId, generation: value.generation,
    operationId: value.operationId, request: value.request });
  if (value.requestDigest !== expected) throw new Error("Sandsurf command digest mismatch");
}

export function createSandsurfGuestCommand(
  value: Omit<SandsurfGuestCommand, "requestDigest">,
): SandsurfGuestCommand {
  const requestDigest = guestCommandDigest(value);
  const command = { ...value, requestDigest };
  validateSandsurfGuestCommand(command);
  return command;
}

function guestCommandDigest(value: Omit<SandsurfGuestCommand, "requestDigest">): string {
  const metadata = sandsurfGuestRequestMetadata(value.request);
  return sandsurfDigest("operation", ["sandsurf-guest-command-v1", value.machineId,
    value.generation, value.operationId, metadata]);
}

export function sandsurfGuestRequestMetadata(request: SandsurfGuestRequest): {
  readonly request: SandsurfGuestRequest;
  readonly binary: readonly { readonly length: number; readonly digest: string }[] | null;
} {
  let bytes: readonly number[] | undefined;
  let metadata = request;
  if (request.kind === "write-input") {
    bytes = request.bytes;
    metadata = { ...request, bytes: [] };
  } else if (request.kind === "filesystem" && (request.request.kind === "write" || request.request.kind === "write-chunk")) {
    if (!Array.isArray(request.request.bytes)) throw new Error("invalid Sandsurf filesystem bytes");
    bytes = request.request.bytes;
    metadata = { ...request, request: { ...request.request, bytes: [] } };
  }
  if (bytes === undefined) return { request: metadata, binary: null };
  if (bytes.length > SANDSURF_MAX_STREAM_BYTES
    || bytes.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) throw new Error("invalid Sandsurf command bytes");
  const payload = Buffer.from(bytes);
  return { request: metadata, binary: payload.length === 0 ? [] : [{
    length: payload.length, digest: createHash("sha256").update(payload).digest("hex"),
  }] };
}

function validateGuestRequest(value: SandsurfGuestRequest): void {
  const fields = value;
  switch (fields.kind) {
    case "spawn": validateExecutionRequest(fields.request); break;
    case "write-input":
      identity(fields.executionId);
      if (fields.terminalLeaseId !== null) identity(fields.terminalLeaseId);
      if (!Array.isArray(fields.bytes) || fields.bytes.length < 1 || fields.bytes.length > SANDSURF_MAX_STREAM_BYTES
        || fields.bytes.some((byte) => typeof byte !== "number" || !Number.isInteger(byte) || byte < 0 || byte > 255)) {
        throw new Error("invalid Sandsurf input bytes");
      }
      break;
    case "close-input":
      identity(fields.executionId);
      if (fields.terminalLeaseId !== null) identity(fields.terminalLeaseId);
      break;
    case "acquire-terminal-input":
    case "release-terminal-input":
      identity(fields.executionId); identity(fields.terminalLeaseId); break;
    case "resize-terminal": identity(fields.executionId); validateTerminalSize(fields.size); break;
    case "signal":
      identity(fields.executionId); counter(fields.signal);
      if (fields.signal < 1 || fields.signal > 64 || typeof fields.group !== "boolean") throw new Error("invalid Sandsurf signal");
      break;
    case "terminate":
      identity(fields.executionId); counter(fields.graceMillis);
      if (fields.graceMillis > 60_000) throw new Error("invalid Sandsurf termination grace");
      break;
    case "filesystem": break;
    default: throw new Error("unknown Sandsurf guest command");
  }
}

export function validateExecutionRequest(value: unknown): asserts value is ExecutionRequest {
  validateProtocol("SpawnRequest", value);
  identity(value.machineId); identity(value.executionId); identity(value.operationId); counter(value.generation); counter(value.outputBytes);
  if (value.generation === 0 || value.outputBytes === 0 || !Array.isArray(value.argv) || value.argv.length < 1 || value.argv.length > 4096
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
    throw new Error("invalid Sandsurf Linux user");
  }
  if (value.stdio === "terminal") validateTerminalSize(value.terminalSize);
  else if (value.stdio !== "pipes" || value.terminalSize !== null) throw new Error("invalid Sandsurf stdio mode");
  if (value.activeDeadlineMillis !== null) {
    counter(value.activeDeadlineMillis);
    if (value.activeDeadlineMillis === 0 || value.activeDeadlineMillis > 30 * 24 * 60 * 60 * 1000) throw new Error("invalid Sandsurf active process deadline");
  }
  if (value.elapsedDeadlineUnixMillis !== null) { counter(value.elapsedDeadlineUnixMillis); if (value.elapsedDeadlineUnixMillis === 0) throw new Error("invalid Sandsurf elapsed process deadline"); }
}

function validateTerminalSize(value: unknown): asserts value is SandsurfTerminalSize {
  validateProtocol("TerminalSize", value);
  for (const name of ["columns", "rows", "pixelWidth", "pixelHeight"] as const) {
    counter(value[name]); if (value[name] > 0xffff) throw new Error("invalid Sandsurf terminal dimension");
  }
  if (value.columns === 0 || value.rows === 0) throw new Error("invalid Sandsurf terminal size");
}

function guestPath(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 4096 || !value.startsWith("/")
    || value.includes("\0")) throw new Error("invalid Sandsurf guest path");
}

export function validateSandsurfOutputBoundary(value: unknown): asserts value is OutputBoundary {
  validateProtocol("OutputBoundary", value);
  sha256(value.finalHash);
  const boundary = value;
  if (BigInt(boundary.stdoutBytes) + BigInt(boundary.stderrBytes) + BigInt(boundary.terminalBytes) !== BigInt(boundary.finalCursor)
    || (boundary.chunks === 0) !== (boundary.finalCursor === 0) || boundary.chunks > boundary.finalCursor
    || BigInt(boundary.finalCursor) > BigInt(boundary.chunks) * BigInt(SANDSURF_MAX_STREAM_BYTES)) {
    throw new Error("inconsistent Sandsurf output boundary");
  }
}

export function validateSandsurfRelease(value: unknown): asserts value is SandsurfReleaseRequest {
  validateProtocol("ReleaseRequest", value);
  identity(value.operationId); sha256(value.receiptDigest); validateSandsurfOutputBoundary(value.output);
  const disposition = value.disposition;
  const fields = disposition;
  switch (fields.kind) {
    case "complete-capture": {
      const commitment = fields.commitment;
      identity(commitment.storeId); identity(commitment.commitmentId); sha256(commitment.manifestDigest);
      sha256(commitment.receiptDigest); validateSandsurfOutputBoundary(commitment.output);
      break;
    }
    case "continuing-retention": identity(fields.segment); break;
    case "authorized-loss": identity(fields.authorization); break;
    default: throw new Error("unknown release disposition");
  }
  // Coverage, segment ownership and loss decisions are checked by the authority, not this codec.
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
  MAGIC.copy(header); header.writeUInt16BE(SANDSURF_PROTOCOL_VERSION, 4); header[6] = kinds.indexOf(frame.kind) + 1;
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
          if (!this.#header.subarray(0, 4).equals(MAGIC) || this.#header.readUInt16BE(4) !== SANDSURF_PROTOCOL_VERSION || this.#header[7] !== 0) throw new Error("invalid Sandsurf header");
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

/** Same domain-separated canonical encoding as sandsurf-format's Sandsurf domains. */
export function sandsurfDigest(domain: SandsurfDigestDomain, value: unknown): string {
  if (!["machine", "authority", "operation", "receipt", "output", "release", "image", "snapshot", "transfer", "network", "secret", "resource", "exposure"].includes(domain)) throw new Error("unknown digest domain");
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
  string("SANDSURF-COMPUTER-DIGEST-1"); string(`SANDSURF/${domain.toUpperCase()}/1`); visit(value, 0);
  return hash.digest("hex");
}
