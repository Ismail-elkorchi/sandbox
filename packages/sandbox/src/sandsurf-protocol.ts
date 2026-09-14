// Internal Sandsurf wire contract. This does not adapt the prepared-process runtime.
import { createHash } from "node:crypto";

export const SANDSURF_HEADER_BYTES = 24;
export const SANDSURF_MAX_CONTROL_BYTES = 256 * 1024;
export const SANDSURF_MAX_STREAM_BYTES = 64 * 1024;
const MAGIC = Buffer.from("SSF1");

export type SandsurfDigestDomain = "sandbox" | "grant" | "operation" | "receipt" | "output" | "release" | "image" | "checkpoint" | "transfer";
export type SandsurfFrameKind = "control" | "data" | "credit" | "end";
const kinds: readonly SandsurfFrameKind[] = ["control", "data", "credit", "end"];

export interface SandsurfFrame {
  readonly kind: SandsurfFrameKind;
  readonly stream: number;
  readonly sequence: number;
  readonly payload: Uint8Array;
}

export interface SandsurfMutation {
  readonly sandboxId: string;
  readonly epoch: number;
  readonly operationId: string;
  readonly grantId: string;
  readonly expectedRevision: number;
  readonly requestDigest: string;
}

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
  record(value, ["sandboxId", "epoch", "operationId", "grantId", "expectedRevision", "requestDigest"]);
  identity(value.sandboxId); identity(value.operationId); identity(value.grantId);
  counter(value.epoch); counter(value.expectedRevision); sha256(value.requestDigest);
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
  const header = Buffer.alloc(SANDSURF_HEADER_BYTES);
  MAGIC.copy(header); header.writeUInt16BE(1, 4); header[6] = kinds.indexOf(frame.kind) + 1;
  header.writeUInt32BE(frame.stream, 8); header.writeBigUInt64BE(BigInt(frame.sequence), 12);
  header.writeUInt32BE(frame.payload.byteLength, 20);
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
          if (!this.#header.subarray(0, 4).equals(MAGIC) || this.#header.readUInt16BE(4) !== 1 || this.#header[7] !== 0) throw new Error("invalid Sandsurf header");
          const kind = kinds[(this.#header[6] ?? 0) - 1];
          if (kind === undefined) throw new Error("unknown Sandsurf frame kind");
          const stream = this.#header.readUInt32BE(8);
          const sequence = Number(this.#header.readBigUInt64BE(12));
          const length = this.#header.readUInt32BE(20);
          validateFrame(kind, stream, sequence, length);
          this.#kind = kind; this.#stream = stream; this.#sequence = sequence;
          this.#payload = Buffer.alloc(length); // Header bounds checked before allocation.
          this.#payloadUsed = 0;
        }
        const count = Math.min(this.#payload.length - this.#payloadUsed, bytes.length - offset);
        this.#payload.set(bytes.subarray(offset, offset + count), this.#payloadUsed);
        this.#payloadUsed += count; offset += count;
        if (this.#payloadUsed !== this.#payload.length) continue;
        const frame = { kind: this.#kind, stream: this.#stream, sequence: this.#sequence, payload: this.#payload };
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
  if (!["sandbox", "grant", "operation", "receipt", "output", "release", "image", "checkpoint", "transfer"].includes(domain)) throw new Error("unknown digest domain");
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
