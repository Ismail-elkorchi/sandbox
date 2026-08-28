import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
import { readdir } from "node:fs/promises";
import net from "node:net";
import { fileURLToPath } from "node:url";
import {
  adoptExecutionRepositoryRoot,
  authToken,
  createExecutionDirectory,
  digestRun,
  executionDirectory,
  expireRecord,
  normalizeLimits,
  readOutput,
  readReceipt,
  readRecord,
  removeExecutionDirectory,
  repositoryIdentity,
  serializeRunForHost,
  validateDetachedRun,
  validateExecutionId,
  writeRecord,
  type ExecutionRecord,
  type ExecutionRepositoryLimits,
} from "./execution-record.js";
import type {
  SandboxExecutionObservation,
  SandboxExecutionOutput,
  SandboxExecutionQuery,
  SandboxExecutionReconciliation,
  SandboxExecutionRepository,
  SandboxExecutionRepositoryOptions,
  SandboxExecutionRequest,
} from "./execution.js";

const EMPTY_OUTPUT: SandboxExecutionOutput = Object.freeze({
  cursorStart: 0,
  cursorEnd: 0,
  availableCursorEnd: 0,
  stdoutBytes: 0,
  stderrBytes: 0,
  cursorExpired: false,
  chunks: Object.freeze([]),
});

export async function openSandboxExecutionRepository(
  options: SandboxExecutionRepositoryOptions,
): Promise<SandboxExecutionRepository> {
  if (typeof options !== "object" || options === null) throw new TypeError("Execution repository options must be an object.");
  const root = await adoptExecutionRepositoryRoot(options.directory);
  const repository = new ExecutionRepositoryImplementation(root, normalizeLimits(options));
  await repository.pruneExpiredRecords();
  return repository;
}

class ExecutionRepositoryImplementation implements SandboxExecutionRepository {
  readonly identity: string;
  readonly durability = "application-process" as const;
  #closed = false;

  constructor(
    private readonly root: string,
    private readonly limits: ExecutionRepositoryLimits,
  ) {
    this.identity = repositoryIdentity(root);
  }

  async prepare(request: SandboxExecutionRequest, query: SandboxExecutionQuery = {}): Promise<SandboxExecutionObservation> {
    this.#ensureOpen();
    if (typeof request !== "object" || request === null) throw new TypeError("Sandbox execution request must be an object.");
    validateExecutionId(request.executionId);
    validateDetachedRun(request.run, this.limits.maxRetainedOutputBytes);
    const requestDigest = digestRun(request.run);
    const directory = executionDirectory(this.root, request.executionId);
    const created = await createExecutionDirectory(directory);
    if (!created) {
      const existing = await this.#readKnownRecord(directory, request.executionId);
      if (existing !== undefined && existing.requestDigest !== requestDigest) {
        throw new Error(`Execution identity ${request.executionId} is already bound to a different request.`);
      }
      return this.inspect(request.executionId, query);
    }

    const token = authToken();
    const createdAtMs = Date.now();
    await writeRecord(directory, {
      schemaVersion: 1,
      phase: "preparing",
      executionId: request.executionId,
      requestDigest,
      createdAtMs,
      workerPid: 0,
      authToken: token,
    });

    const worker = fileURLToPath(new URL("./execution-worker.js", import.meta.url));
    const child = spawn(process.execPath, [worker, directory], {
      detached: true,
      windowsHide: true,
      stdio: ["ignore", "ignore", "ignore", "pipe"],
      env: { LANG: "C", LC_ALL: "C" },
    });
    const workerPid = child.pid;
    if (workerPid === undefined || workerPid < 1) {
      await this.#recordRejectedStart(directory, request.executionId, requestDigest, createdAtMs, token, "Detached execution host did not receive a process ID.");
      throw new Error("Detached execution host did not receive a process ID.");
    }
    await writeRecord(directory, {
      schemaVersion: 1,
      phase: "preparing",
      executionId: request.executionId,
      requestDigest,
      createdAtMs,
      workerPid,
      authToken: token,
    });
    const input = child.stdio[3];
    if (input === null || input === undefined || typeof input === "number" || !("end" in input)) {
      child.kill("SIGKILL");
      await this.#recordRejectedStart(directory, request.executionId, requestDigest, createdAtMs, token, "Detached execution host input channel is unavailable.", workerPid);
      throw new Error("Detached execution host input channel is unavailable.");
    }
    const payload = serializeRunForHost(request.run, this.limits);
    if (Buffer.byteLength(payload) > 2 * 1024 * 1024) {
      child.kill("SIGKILL");
      await this.#recordRejectedStart(directory, request.executionId, requestDigest, createdAtMs, token, "Detached execution request exceeds the 2 MiB admission bound.", workerPid);
      throw new RangeError("Detached execution request exceeds the 2 MiB admission bound.");
    }
    await new Promise<void>((resolve, reject) => {
      input.once("error", reject);
      input.end(payload, () => resolve());
    });
    child.unref();
    return this.inspect(request.executionId, { ...query, waitMs: query.waitMs ?? this.limits.startupTimeoutMs });
  }

  async inspect(executionId: string, query: SandboxExecutionQuery = {}): Promise<SandboxExecutionObservation> {
    this.#ensureOpen();
    validateExecutionId(executionId);
    const afterCursor = nonnegative(query.afterCursor ?? 0, "afterCursor");
    const maxBytes = positive(query.maxBytes ?? 256 * 1024, "maxBytes");
    const waitMs = nonnegative(query.waitMs ?? 0, "waitMs");
    const directory = executionDirectory(this.root, executionId);
    const deadline = Date.now() + waitMs;
    let initialSignature = "";
    do {
      let record: ExecutionRecord;
      try {
        record = await readRecord(directory);
      } catch (error) {
        if (nodeCode(error) === "ENOENT") return unknown(executionId, "not-found", "No execution record exists for this identity.");
        return unknown(executionId, "corrupt-record", bounded(error));
      }
      if (record.executionId !== executionId) return unknown(executionId, "corrupt-record", "Execution record identity does not match its directory.");
      if ((record.phase === "settled" || record.phase === "rejected") && Date.now() >= record.expiresAtMs) {
        await expireRecord(directory, record).catch(() => undefined);
        return Object.freeze({ kind: "expired", executionId, requestDigest: record.requestDigest, expiredAtMs: record.expiresAtMs, output: EMPTY_OUTPUT });
      }
      if (record.phase === "expired") {
        if (Date.now() >= record.expiredAtMs + this.limits.expiredIdentityRetentionMs) {
          await removeExecutionDirectory(directory);
          return unknown(executionId, "not-found", "The expired execution identity is no longer retained.");
        }
        return Object.freeze({ kind: "expired", executionId, requestDigest: record.requestDigest, expiredAtMs: record.expiredAtMs, output: EMPTY_OUTPUT });
      }
      let output;
      try {
        output = await readOutput(
          directory,
          afterCursor,
          maxBytes,
          record.phase === "settled" ? record.cursorEnd : undefined,
          record.phase === "settled" ? record.outputHash : undefined,
        );
      } catch (error) {
        return unknown(executionId, "corrupt-record", bounded(error), record.requestDigest);
      }
      if (record.phase === "settled") {
        try {
          return Object.freeze({ kind: "settled", executionId, requestDigest: record.requestDigest, result: await readReceipt(directory), output });
        } catch (error) {
          return unknown(executionId, "corrupt-record", bounded(error), record.requestDigest);
        }
      }
      if (record.phase === "rejected") return Object.freeze({ kind: "rejected", executionId, requestDigest: record.requestDigest, error: record.error, output });
      if (record.phase === "unknown") return unknown(executionId, "execution-host-unreachable", record.diagnostic, record.requestDigest, output);
      if (record.phase === "prepared") return Object.freeze({
        kind: "prepared", executionId, requestDigest: record.requestDigest,
        policyDigest: record.policyDigest, executionDigest: record.executionDigest,
        summary: record.summary, enforcement: record.enforcement, expiresAtMs: record.expiresAtMs, output,
      });

      const signature = `${record.phase}:${output.cursorEnd}`;
      if (initialSignature.length === 0) initialSignature = signature;
      else if (signature !== initialSignature) {
        return record.phase === "running"
          ? Object.freeze({ kind: "running", executionId, requestDigest: record.requestDigest, processId: record.processId, output })
          : Object.freeze({ kind: "preparing", executionId, requestDigest: record.requestDigest, output });
      }
      if (Date.now() >= deadline) {
        const reachable = record.endpoint !== undefined && await sendControl(record.endpoint, record.authToken, { kind: "ping" }).then(() => true, () => false);
        if (!reachable && Date.now() - record.createdAtMs >= this.limits.startupTimeoutMs) {
          return unknown(executionId, "execution-host-unreachable", "The detached execution host cannot be authenticated; the external effect outcome is unknown.", record.requestDigest, output);
        }
        return record.phase === "running"
          ? Object.freeze({ kind: "running", executionId, requestDigest: record.requestDigest, processId: record.processId, output })
          : Object.freeze({ kind: "preparing", executionId, requestDigest: record.requestDigest, output });
      }
      await sleep(Math.min(25, Math.max(1, deadline - Date.now())));
    } while (true);
  }

  async activate(executionId: string, expected: { policyDigest: string; executionDigest: string }): Promise<void> {
    if (typeof expected !== "object" || expected === null || typeof expected.policyDigest !== "string" || typeof expected.executionDigest !== "string") {
      throw new TypeError("Sandbox activation requires the exact prepared policy and execution digests.");
    }
    await this.#control(executionId, { kind: "activate", policyDigest: expected.policyDigest, executionDigest: expected.executionDigest });
  }

  async writeInput(executionId: string, data: Uint8Array): Promise<void> {
    if (!(data instanceof Uint8Array)) throw new TypeError("Sandbox input must be a Uint8Array.");
    if (data.byteLength > 64 * 1024) throw new RangeError("One sandbox input write cannot exceed 64 KiB.");
    await this.#control(executionId, { kind: "write", dataBase64: Buffer.from(data).toString("base64") });
  }

  async closeInput(executionId: string): Promise<void> {
    await this.#control(executionId, { kind: "close-input" });
  }

  async terminate(executionId: string): Promise<void> {
    await this.#control(executionId, { kind: "terminate" });
  }

  async reconcile(): Promise<SandboxExecutionReconciliation> {
    this.#ensureOpen();
    const settled: SandboxExecutionObservation[] = [];
    const unresolved: SandboxExecutionObservation[] = [];
    for (const entry of await readdir(this.root, { withFileTypes: true })) {
      if (!entry.isDirectory() || !entry.name.startsWith("execution-")) continue;
      const directory = `${this.root}/${entry.name}`;
      try {
        const record = await readRecord(directory);
        const observation = await this.inspect(record.executionId);
        if (observation.kind === "settled" || observation.kind === "rejected") settled.push(observation);
        else unresolved.push(observation);
      } catch (error) {
        unresolved.push(unknown(entry.name, "corrupt-record", bounded(error)));
      }
    }
    return Object.freeze({ settled: Object.freeze(settled), unresolved: Object.freeze(unresolved) });
  }

  async forget(executionId: string): Promise<void> {
    this.#ensureOpen();
    validateExecutionId(executionId);
    const directory = executionDirectory(this.root, executionId);
    const record = await readRecord(directory);
    if (record.phase === "preparing" || record.phase === "prepared" || record.phase === "running") throw new Error("A live or uncertain execution cannot be forgotten.");
    await removeExecutionDirectory(directory);
  }

  async close(): Promise<void> {
    this.#closed = true;
  }

  async pruneExpiredRecords(): Promise<void> {
    for (const entry of await readdir(this.root, { withFileTypes: true })) {
      if (!entry.isDirectory() || !entry.name.startsWith("execution-")) continue;
      const directory = `${this.root}/${entry.name}`;
      try {
        const record = await readRecord(directory);
        if ((record.phase === "settled" || record.phase === "rejected") && Date.now() >= record.expiresAtMs) await expireRecord(directory, record);
        else if (record.phase === "expired" && Date.now() >= record.expiredAtMs + this.limits.expiredIdentityRetentionMs) await removeExecutionDirectory(directory);
      } catch {
        // Corrupt records remain available for explicit reconciliation and diagnosis.
      }
    }
  }

  async #control(executionId: string, command: Record<string, unknown>): Promise<void> {
    this.#ensureOpen();
    validateExecutionId(executionId);
    const record = await readRecord(executionDirectory(this.root, executionId));
    if ((record.phase !== "preparing" && record.phase !== "prepared" && record.phase !== "running") || record.endpoint === undefined) {
      throw new Error(`Execution ${executionId} does not have a reachable live control endpoint.`);
    }
    await sendControl(record.endpoint, record.authToken, command);
  }

  async #readKnownRecord(directory: string, executionId: string): Promise<ExecutionRecord | undefined> {
    const deadline = Date.now() + this.limits.startupTimeoutMs;
    while (true) {
      try {
        const record = await readRecord(directory);
        if (record.executionId !== executionId) throw new Error("Execution record identity mismatch.");
        return record;
      } catch (error) {
        if (nodeCode(error) !== "ENOENT" || Date.now() >= deadline) throw error;
        await sleep(10);
      }
    }
  }

  async #recordRejectedStart(directory: string, executionId: string, requestDigest: string, createdAtMs: number, token: string, message: string, workerPid = 0): Promise<void> {
    const now = Date.now();
    await writeRecord(directory, {
      schemaVersion: 1,
      phase: "rejected",
      executionId,
      requestDigest,
      createdAtMs,
      workerPid,
      authToken: token,
      endpoint: 0,
      rejectedAtMs: now,
      expiresAtMs: now + this.limits.completedRetentionMs,
      error: { code: "spawn.detached_host", message, phase: "spawn", targetExecuted: false },
    });
  }

  #ensureOpen(): void {
    if (this.#closed) throw new Error("Sandbox execution repository is closed.");
  }
}

async function sendControl(endpoint: number, token: string, command: Record<string, unknown>): Promise<void> {
  if (!Number.isSafeInteger(endpoint) || endpoint < 1 || endpoint > 65_535) throw new Error("Execution control endpoint is invalid.");
  const payload = `${JSON.stringify({ token, ...command })}\n`;
  if (Buffer.byteLength(payload) > 128 * 1024) throw new RangeError("Execution control request is too large.");
  await new Promise<void>((resolve, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port: endpoint });
    let response = "";
    socket.setTimeout(2_000, () => socket.destroy(new Error("Execution control request timed out.")));
    socket.once("connect", () => socket.write(payload));
    socket.on("data", (chunk: Buffer) => {
      response += chunk.toString("utf8");
      if (Buffer.byteLength(response) > 64 * 1024) socket.destroy(new Error("Execution control response is too large."));
    });
    socket.once("error", reject);
    socket.once("end", () => {
      try {
        const value = JSON.parse(response) as { accepted?: unknown; error?: unknown };
        if (value.accepted !== true) throw new Error(typeof value.error === "string" ? value.error : "Execution control request was rejected.");
        resolve();
      } catch (error) {
        reject(error);
      }
    });
  });
}

function unknown(
  executionId: string,
  reason: "not-found" | "execution-host-unreachable" | "corrupt-record",
  diagnostic: string,
  requestDigest?: string,
  output = EMPTY_OUTPUT,
): SandboxExecutionObservation {
  return Object.freeze({ kind: "unknown", executionId, ...(requestDigest === undefined ? {} : { requestDigest }), reason, diagnostic, output });
}

function bounded(error: unknown): string {
  const value = error instanceof Error ? error.message : String(error);
  return value.length <= 4096 ? value : `${value.slice(0, 4093)}...`;
}

function positive(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${label} must be a positive safe integer.`);
  return value;
}

function nonnegative(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} must be a non-negative safe integer.`);
  return value;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function nodeCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" ? error.code : undefined;
}
