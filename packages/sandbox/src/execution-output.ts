import { Buffer } from "node:buffer";
import { constants } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import { join } from "node:path";
import { digestRun, OUTPUT_FILE, ZERO_HASH } from "./execution-record.js";
import type { SandboxExecutionAvailableOutput, SandboxExecutionOutputChunk, SandboxExecutionReceipt } from "./execution.js";
import { nodeCode } from "./execution-storage.js";

export const OUTPUT_CHUNK_BYTES = 16 * 1024;
const MAX_LINE_BYTES = 24 * 1024;
const READ_BYTES = 32 * 1024;

interface StoredChunk {
  sequence: number; cursorStart: number; cursorEnd: number; stream: "stdout" | "stderr";
  dataBase64: string; previousHash: string; hash: string;
}
interface Boundary {
  offset: number; sequence: number; cursor: number; hash: string; stdoutBytes: number; stderrBytes: number;
}
interface Index {
  device: bigint; inode: bigint; size: number; modified: bigint; changed: bigint;
  end: Boundary; checkpoints: Boundary[];
}
export interface OutputReadMetrics { bytesRead: number; recordsRead: number; rebuilds: number }

export async function appendOutput(directory: string, chunk: Omit<StoredChunk, "hash">): Promise<string> {
  const hash = digestRun(chunk).slice(7);
  const stored = { ...chunk, hash };
  parseChunk(stored, { ...emptyBoundary(), sequence: chunk.sequence - 1, cursor: chunk.cursorStart, hash: chunk.previousHash });
  const line = Buffer.from(JSON.stringify(stored) + "\n");
  const file = await open(join(directory, OUTPUT_FILE), constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    let offset = 0;
    while (offset < line.length) {
      const written = await file.write(line, offset, line.length - offset);
      if (written.bytesWritten === 0) throw new Error("Execution output write made no progress.");
      offset += written.bytesWritten;
    }
    await file.sync();
  } finally { await file.close(); }
  return hash;
}

// Only verified, in-memory checkpoints are cached. Restart performs one cold
// scan. No on-disk index can assert authority over the original byte records.
export class ExecutionOutputReader {
  readonly metrics: OutputReadMetrics = { bytesRead: 0, recordsRead: 0, rebuilds: 0 };
  #indexes = new Map<string, Index>();
  #pending = new Map<string, Promise<unknown>>();

  read(directory: string, afterCursor: number, maxBytes: number, outputLimit: number, receipt?: SandboxExecutionReceipt): Promise<SandboxExecutionAvailableOutput> {
    const previous = this.#pending.get(directory) ?? Promise.resolve();
    const task = previous.catch(() => undefined).then(() => this.#read(directory, afterCursor, maxBytes, outputLimit, receipt));
    this.#pending.set(directory, task);
    void task.finally(() => { if (this.#pending.get(directory) === task) this.#pending.delete(directory); }).catch(() => undefined);
    return task;
  }
  forget(directory: string): void { this.#indexes.delete(directory); }
  close(): void { this.#indexes.clear(); }

  async #read(directory: string, afterCursor: number, maxBytes: number, outputLimit: number, receipt?: SandboxExecutionReceipt): Promise<SandboxExecutionAvailableOutput> {
    let file: FileHandle;
    try { file = await open(join(directory, OUTPUT_FILE), constants.O_RDONLY | constants.O_NOFOLLOW); }
    catch (error) {
      this.#indexes.delete(directory);
      if (nodeCode(error) === "ENOENT" && receipt === undefined) return output(afterCursor, emptyBoundary(), []);
      throw error;
    }
    try {
      const stat = await file.stat({ bigint: true });
      if (!stat.isFile() || stat.size > BigInt(Number.MAX_SAFE_INTEGER) || stat.size > BigInt(outputLimit) * 512n) throw new TypeError("Execution output exceeds its storage geometry.");
      const size = Number(stat.size);
      let index = this.#indexes.get(directory);
      if (index === undefined || index.device !== stat.dev || index.inode !== stat.ino || size < index.size
        || (size === index.size && (index.modified !== stat.mtimeNs || index.changed !== stat.ctimeNs))) {
        index = { device: stat.dev, inode: stat.ino, size: 0, modified: 0n, changed: 0n, end: emptyBoundary(), checkpoints: [emptyBoundary()] };
        this.metrics.rebuilds++;
      }
      const end = { ...index.end };
      let checkpoint = index.checkpoints.at(-1)!;
      for await (const item of this.#lines(file, end.offset, size)) {
        const chunk = parseChunk(JSON.parse(item.text), end);
        this.metrics.recordsRead++;
        advance(end, chunk, item.end);
        if (end.cursor > outputLimit) throw new TypeError("Execution output exceeds its reserved byte limit.");
        if (end.cursor - checkpoint.cursor >= 64 * 1024 || end.sequence - checkpoint.sequence >= 1024) {
          checkpoint = { ...end }; index.checkpoints.push(checkpoint);
        }
      }
      if (receipt !== undefined && (end.offset !== size || end.cursor !== receipt.finalCursor || end.hash !== receipt.outputHash
        || end.stdoutBytes !== receipt.stdoutBytes || end.stderrBytes !== receipt.stderrBytes)) {
        throw new TypeError("Execution output does not match its terminal receipt.");
      }
      index.end = end; index.size = size; index.modified = stat.mtimeNs; index.changed = stat.ctimeNs;
      this.#indexes.delete(directory); this.#indexes.set(directory, index);
      while (this.#indexes.size > 8) this.#indexes.delete(this.#indexes.keys().next().value!);
      if (afterCursor > end.cursor) throw new RangeError("Invalid execution output cursor.");
      const chunks: SandboxExecutionOutputChunk[] = [];
      if (afterCursor < end.cursor) {
        let low = 0; let high = index.checkpoints.length;
        while (low + 1 < high) {
          const mid = Math.floor((low + high) / 2);
          if (index.checkpoints[mid]!.cursor <= afterCursor) low = mid; else high = mid;
        }
        const position = { ...index.checkpoints[low]! };
        let remaining = maxBytes;
        for await (const item of this.#lines(file, position.offset, end.offset)) {
          const chunk = parseChunk(JSON.parse(item.text), position);
          this.metrics.recordsRead++;
          advance(position, chunk, item.end);
          // Checkpoint endpoints come exclusively from the verified cold/tail scan.
          const next = index.checkpoints[low + 1];
          if (next?.offset === position.offset) {
            if (next.hash !== position.hash) throw new TypeError("Execution output checkpoint binding changed.");
            low++;
          }
          if (chunk.cursorEnd > afterCursor && remaining > 0) {
            const offset = Math.max(0, afterCursor - chunk.cursorStart);
            const data = Buffer.from(chunk.dataBase64, "base64").subarray(offset, offset + remaining);
            const start = chunk.cursorStart + offset;
            chunks.push(Object.freeze({ cursorStart: start, cursorEnd: start + data.length, stream: chunk.stream, data: Buffer.from(data) }));
            remaining -= data.length;
          }
          if (position.offset === end.offset && position.hash !== end.hash) throw new TypeError("Execution output final binding changed.");
          // Verify through the next trusted boundary, including when the caller
          // requested only one byte inside a record. Never trust a self-hash alone.
          if (remaining === 0 && (next?.offset === position.offset || position.offset === end.offset)) break;
        }
      }
      // Detect replacement/truncation during range access; an append may leave
      // this observation at its earlier verified boundary.
      const after = await file.stat({ bigint: true });
      if (after.size < stat.size || (after.size === stat.size && (after.mtimeNs !== stat.mtimeNs || after.ctimeNs !== stat.ctimeNs))) {
        throw new TypeError("Execution output changed during retrieval.");
      }
      return output(afterCursor, end, chunks);
    } catch (error) {
      this.#indexes.delete(directory);
      throw error;
    } finally { await file.close(); }
  }

  async *#lines(file: FileHandle, start: number, end: number): AsyncGenerator<{ text: string; end: number }> {
    let position = start; let pending = Buffer.alloc(0); let lineEnd = start;
    while (position < end) {
      const buffer = Buffer.allocUnsafe(Math.min(READ_BYTES, end - position));
      const { bytesRead } = await file.read(buffer, 0, buffer.length, position);
      this.metrics.bytesRead += bytesRead;
      if (bytesRead === 0) throw new TypeError("Execution output was truncated during retrieval.");
      position += bytesRead;
      pending = Buffer.concat([pending, buffer.subarray(0, bytesRead)]);
      let newline: number;
      while ((newline = pending.indexOf(10)) >= 0) {
        if (newline === 0 || newline > MAX_LINE_BYTES) throw new TypeError("Invalid execution output record size.");
        lineEnd += newline + 1;
        const text = pending.subarray(0, newline).toString("utf8");
        pending = pending.subarray(newline + 1);
        yield { text, end: lineEnd };
      }
      if (pending.length > MAX_LINE_BYTES) throw new TypeError("Invalid execution output record size.");
    }
    // A live append can end in a partial record; never advance past it.
  }
}

function parseChunk(value: unknown, previous: Boundary): StoredChunk {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("Invalid execution output record.");
  const chunk = value as StoredChunk;
  if (Object.keys(chunk).some((key) => !["sequence", "cursorStart", "cursorEnd", "stream", "dataBase64", "previousHash", "hash"].includes(key))) {
    throw new TypeError("Invalid execution output record fields.");
  }
  if (!Number.isSafeInteger(chunk.sequence) || chunk.sequence !== previous.sequence + 1
    || chunk.cursorStart !== previous.cursor || !Number.isSafeInteger(chunk.cursorEnd) || chunk.cursorEnd <= chunk.cursorStart
    || chunk.cursorEnd - chunk.cursorStart > OUTPUT_CHUNK_BYTES || (chunk.stream !== "stdout" && chunk.stream !== "stderr")
    || typeof chunk.dataBase64 !== "string" || chunk.previousHash !== previous.hash || typeof chunk.hash !== "string") {
    throw new TypeError("Execution output chunk geometry or hash chain is invalid.");
  }
  const bytes = Buffer.from(chunk.dataBase64, "base64");
  if (bytes.toString("base64") !== chunk.dataBase64 || bytes.length !== chunk.cursorEnd - chunk.cursorStart) throw new TypeError("Execution output bytes are invalid.");
  const { hash, ...unsigned } = chunk;
  if (digestRun(unsigned).slice(7) !== hash) throw new TypeError("Execution output chunk checksum is invalid.");
  return chunk;
}
function emptyBoundary(): Boundary { return { offset: 0, sequence: 0, cursor: 0, hash: ZERO_HASH, stdoutBytes: 0, stderrBytes: 0 }; }
function advance(boundary: Boundary, chunk: StoredChunk, offset: number): void {
  boundary.offset = offset; boundary.sequence = chunk.sequence; boundary.hash = chunk.hash; boundary.cursor = chunk.cursorEnd;
  if (chunk.stream === "stdout") boundary.stdoutBytes += chunk.cursorEnd - chunk.cursorStart;
  else boundary.stderrBytes += chunk.cursorEnd - chunk.cursorStart;
}
function output(afterCursor: number, end: Boundary, chunks: SandboxExecutionOutputChunk[]): SandboxExecutionAvailableOutput {
  if (afterCursor > end.cursor) throw new RangeError("Invalid execution output cursor.");
  return Object.freeze({ kind: "available", cursorStart: afterCursor, cursorEnd: chunks.at(-1)?.cursorEnd ?? afterCursor,
    availableCursorEnd: end.cursor, stdoutBytes: end.stdoutBytes, stderrBytes: end.stderrBytes, chunks: Object.freeze(chunks) });
}
