import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, open } from "node:fs/promises";
import { constants } from "node:fs";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import {
  adoptExecutionRepositoryRoot, admitExecution, authToken, digestRun, executionDirectory,
  finishRetirement, initializeRepository, inventory, metadataReservation, normalizeLimits, OUTPUT_FILE,
  readControl, readRecord, retireExecution, serializeRunForHost, terminalReceipt,
  validateDetachedRun, validateExecutionId, writeRecord, ZERO_HASH,
  type ExecutionRecord, type ExecutionRepositoryLimits, type ExecutionPreparingRecord,
} from "./execution-record.js";
import { ExecutionOutputReader } from "./execution-output.js";
import { SandboxExecutionControlError, sendControl, type ControlCommand } from "./execution-control.js";
import { nodeCode } from "./execution-storage.js";
import type {
  SandboxExecutionObservation, SandboxExecutionOutput, SandboxExecutionQuery, SandboxExecutionInventoryQuery,
  SandboxExecutionReconciliation, SandboxExecutionRepository, SandboxExecutionRepositoryOptions, SandboxExecutionRequest,
} from "./execution.js";
import { repositoryIdentity } from "./execution-record.js";

const NO_OUTPUT = Object.freeze({ kind: "not-requested" as const });
export async function openSandboxExecutionRepository(options: SandboxExecutionRepositoryOptions): Promise<SandboxExecutionRepository> {
  if (typeof options !== "object" || options === null || Array.isArray(options)) throw new TypeError("Execution repository options must be an object.");
  const limits = normalizeLimits(options);
  const root = await adoptExecutionRepositoryRoot(options.directory);
  await initializeRepository(root, limits);
  return new ExecutionRepositoryImplementation(root, limits);
}

class ExecutionRepositoryImplementation implements SandboxExecutionRepository {
  readonly identity: string;
  readonly durability = "application-process" as const;
  #closed = false;
  #output = new ExecutionOutputReader();
  constructor(private readonly root: string, private readonly limits: ExecutionRepositoryLimits) { this.identity = repositoryIdentity(root); }

  async prepare(request: SandboxExecutionRequest, query: SandboxExecutionQuery = {}): Promise<SandboxExecutionObservation> {
    this.#ensureOpen(); validateQuery(query);
    if (typeof request !== "object" || request === null) throw new TypeError("Sandbox execution request must be an object.");
    validateExecutionId(request.executionId);
    // Canonicalization rejects accessors before any public nested property is read.
    const requestDigest = digestRun(request.run);
    validateDetachedRun(request.run, this.limits.maxRetainedOutputBytes);
    const payload = serializeRunForHost(request.run, this.limits);
    if (Buffer.byteLength(payload) > 2 * 1024 * 1024) throw new RangeError("Detached execution request exceeds the 2 MiB admission bound.");
    const initial: ExecutionPreparingRecord = {
      schemaVersion: 1, contract: "retained-execution", phase: "preparing", executionId: request.executionId,
      requestDigest, createdAtMs: Date.now(), admitterPid: process.pid, workerPid: 0, authToken: authToken(), outputLimit: request.run.resources!.output!.value,
      metadataLimit: metadataReservation(request.run),
    };
    if (!admitExecution(this.root, initial, this.limits)) return this.inspect(request.executionId, query);
    const directory = executionDirectory(this.root, request.executionId);
    let workerPid = 0;
    try {
      await mkdir(directory, { mode: 0o700 });
      const file = await open(join(directory, OUTPUT_FILE), constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
      await file.sync(); await file.close();
      const worker = fileURLToPath(new URL("./execution-worker.js", import.meta.url));
      const child = spawn(process.execPath, [worker, directory, request.executionId], {
        detached: true, windowsHide: true, stdio: ["ignore", "ignore", "ignore", "pipe"], env: { LANG: "C", LC_ALL: "C" },
      });
      const spawned = new Promise<void>((resolve, reject) => { child.once("spawn", resolve); child.once("error", reject); });
      await spawned;
      workerPid = child.pid ?? 0;
      if (workerPid < 1) throw new Error("Detached execution host did not receive a process ID.");
      await writeRecord(directory, { ...initial, workerPid }, "preparing");
      const input = child.stdio[3];
      if (input === null || input === undefined || typeof input === "number" || !("end" in input)) {
        child.kill("SIGKILL"); throw new Error("Detached execution host input channel is unavailable.");
      }
      try {
        await new Promise<void>((resolve, reject) => { input.once("error", reject); input.end(payload, () => resolve()); });
      } catch (error) { child.kill("SIGKILL"); throw error; }
      child.unref();
    } catch {
      const current = await readRecord(directory, request.executionId);
      if (current.phase === "preparing") {
        await writeRecord(directory, terminalReceipt({
          ...initial, phase: "rejected" as const, workerPid, endpoint: 0, rejectedAtMs: Date.now(),
          error: { code: "spawn.detached_host", message: "Detached execution host admission failed.", phase: "spawn" as const, targetExecuted: false },
        }, emptyBoundary()), "preparing");
      }
    }
    return this.inspect(request.executionId, { ...query, waitMs: query.waitMs ?? this.limits.startupTimeoutMs });
  }

  async inspect(executionId: string, query: SandboxExecutionQuery = {}): Promise<SandboxExecutionObservation> {
    this.#ensureOpen(); validateExecutionId(executionId);
    const { afterCursor, maxBytes, waitMs } = validateQuery(query);
    const directory = executionDirectory(this.root, executionId);
    const deadline = performance.now() + waitMs;
    let signature: string | undefined;
    while (true) {
      let record: ExecutionRecord;
      try { record = await readRecord(directory, executionId); }
      catch (error) { return storageObservation(executionId, error); }
      if (isFinal(record) || record.phase === "unknown") return this.#observe(record, afterCursor, maxBytes);
      const observation = await this.#observe(record, afterCursor, maxBytes);
      const currentSignature = record.phase + ":" + (observation.output.kind === "available" ? observation.output.cursorEnd : "");
      const changed = signature !== undefined && signature !== currentSignature;
      signature ??= currentSignature;
      if (record.phase !== "prepared" && !changed && performance.now() < deadline) {
        await sleep(Math.min(25, Math.max(1, deadline - performance.now()))); continue;
      }
      if (record.endpoint === undefined && Date.now() - record.createdAtMs < this.limits.startupTimeoutMs) return observation;
      try {
        await sendControl(record.endpoint ?? 0, record.authToken, { kind: "ping", id: randomUUID() });
        // A successful ping also races with publication. Always use current state.
        const current = await readRecord(directory, executionId);
        return this.#observe(current, afterCursor, maxBytes);
      } catch (error) {
        if (!(error instanceof SandboxExecutionControlError)) return storageObservation(executionId, error, record.requestDigest);
        // Observation retries are read-only and bounded. No client publishes a
        // substitute receipt or derives a final boundary from an earlier poll.
        let current: ExecutionRecord = record;
        for (let attempt = 0; attempt < 2; attempt++) {
          if (attempt > 0) await sleep(10);
          try { current = await readRecord(directory, executionId); }
          catch (storageError) { return storageObservation(executionId, storageError, record.requestDigest); }
          if (isFinal(current) || current.phase === "unknown") return this.#observe(current, afterCursor, maxBytes);
        }
        let failure = error;
        if (current.endpoint !== undefined && current.endpoint !== record.endpoint) {
          try {
            await sendControl(current.endpoint, current.authToken, { kind: "ping", id: randomUUID() });
            return this.#observe(await readRecord(directory, executionId), afterCursor, maxBytes);
          } catch (retryError) {
            if (!(retryError instanceof SandboxExecutionControlError)) return storageObservation(executionId, retryError, current.requestDigest);
            failure = retryError;
            try { current = await readRecord(directory, executionId); }
            catch (storageError) { return storageObservation(executionId, storageError, record.requestDigest); }
            if (isFinal(current) || current.phase === "unknown") return this.#observe(current, afterCursor, maxBytes);
          }
        }
        const output = await this.#readOutput(current, afterCursor, maxBytes);
        return Object.freeze({ kind: "unknown", executionId, requestDigest: current.requestDigest, reason: "execution-host-unreachable",
          diagnostic: failure.message, controlFailure: failure.failure, output });
      }
    }
  }

  async activate(executionId: string, expected: { policyDigest: string; executionDigest: string }): Promise<void> {
    if (typeof expected !== "object" || expected === null) throw new TypeError("Activation requires exact prepared digests.");
    validateDigest(expected.policyDigest); validateDigest(expected.executionDigest);
    await this.#control(executionId, { id: randomUUID(), kind: "activate", policyDigest: expected.policyDigest, executionDigest: expected.executionDigest });
  }
  async writeInput(executionId: string, data: Uint8Array): Promise<void> {
    if (!(data instanceof Uint8Array)) throw new TypeError("Sandbox input must be a Uint8Array.");
    if (data.byteLength > 64 * 1024) throw new RangeError("One sandbox input write cannot exceed 64 KiB.");
    await this.#control(executionId, { id: randomUUID(), kind: "write", dataBase64: Buffer.from(data).toString("base64") });
  }
  async closeInput(executionId: string): Promise<void> { await this.#control(executionId, { id: randomUUID(), kind: "close-input" }); }
  async terminate(executionId: string): Promise<void> { await this.#control(executionId, { id: randomUUID(), kind: "terminate" }); }

  async reconcile(query: SandboxExecutionInventoryQuery = {}): Promise<SandboxExecutionReconciliation> {
    this.#ensureOpen();
    if (typeof query !== "object" || query === null) throw new TypeError("Inventory query must be an object.");
    const afterCursor = nonnegative(query.afterCursor ?? 0, "afterCursor");
    const limit = positive(query.limit ?? 50, "limit");
    if (limit > 100) throw new RangeError("Inventory pages cannot exceed 100 identities.");
    const entries = inventory(this.root, afterCursor, limit + 1);
    const page = entries.slice(0, limit);
    const observations = await Promise.all(page.map((entry) => this.inspect(entry.executionId)));
    return Object.freeze({ observations: Object.freeze(observations), ...(entries.length > limit ? { nextCursor: page.at(-1)!.sequence } : {}) });
  }

  async forget(executionId: string, expected: { receiptDigest: string }): Promise<void> {
    this.#ensureOpen(); validateExecutionId(executionId);
    if (typeof expected !== "object" || expected === null) throw new TypeError("Release requires the terminal receipt digest.");
    validateDigest(expected.receiptDigest);
    const retired = retireExecution(this.root, executionId, expected.receiptDigest);
    this.#output.forget(executionDirectory(this.root, executionId));
    await finishRetirement(this.root, retired);
  }
  async acknowledgeUnknown(executionId: string): Promise<void> {
    this.#ensureOpen(); validateExecutionId(executionId);
    const directory = executionDirectory(this.root, executionId);
    const current = await readRecord(directory, executionId);
    if (current.phase === "retired" && current.reason === "acknowledged-unknown") return finishRetirement(this.root, current);
    const observation = await this.inspect(executionId);
    if (observation.kind !== "unknown" || observation.reason !== "execution-host-unreachable" || isFinal(current)) {
      throw new Error("Only a retained unknown effect can be explicitly acknowledged.");
    }
    if (workerAlive(current.workerPid) || (current.workerPid === 0 && workerAlive(current.admitterPid))) throw new Error("A potentially live execution host cannot be retired.");
    const retired = retireExecution(this.root, executionId, undefined, current);
    this.#output.forget(directory);
    await finishRetirement(this.root, retired);
  }
  async close(): Promise<void> { this.#closed = true; this.#output.close(); }

  async #observe(record: ExecutionRecord, afterCursor: number, maxBytes: number): Promise<SandboxExecutionObservation> {
    const base = { executionId: record.executionId, requestDigest: record.requestDigest, output: await this.#readOutput(record, afterCursor, maxBytes) };
    const preparation = record.phase !== "retired" && record.preparation !== undefined ? { preparation: record.preparation } : {};
    if (record.phase === "settled") return Object.freeze({ ...base, ...preparation, kind: "settled", result: record.result, receipt: record.receipt });
    if (record.phase === "rejected") return Object.freeze({ ...base, ...preparation, kind: "rejected", error: record.error, receipt: record.receipt });
    if (record.phase === "retired") return Object.freeze({ ...base, kind: "retired", reason: record.reason, cleanupPending: record.cleanupPending,
      ...(record.receiptDigest === undefined ? {} : { receiptDigest: record.receiptDigest }) });
    if (record.phase === "unknown") return Object.freeze({ ...base, kind: "unknown", reason: "execution-host-unreachable", diagnostic: record.diagnostic });
    if (record.phase === "prepared") return Object.freeze({ ...base, kind: "prepared", policyDigest: record.policyDigest, executionDigest: record.executionDigest,
      summary: record.summary, enforcement: record.enforcement, expiresAtMs: record.expiresAtMs });
    if (record.phase === "running") return Object.freeze({ ...base, kind: "running", processId: record.processId });
    return Object.freeze({ ...base, kind: "preparing" });
  }
  async #readOutput(record: ExecutionRecord, afterCursor: number, maxBytes: number): Promise<SandboxExecutionOutput> {
    if (maxBytes === 0) return NO_OUTPUT;
    if (record.phase === "retired") return Object.freeze({ kind: "unavailable", reason: "released", diagnostic: "Original output was explicitly released." });
    try {
      return await this.#output.read(executionDirectory(this.root, record.executionId), afterCursor, maxBytes, record.outputLimit,
        record.phase === "settled" || record.phase === "rejected" ? record.receipt : undefined);
    } catch (error) {
      if (error instanceof RangeError) throw error;
      return Object.freeze({ kind: "unavailable", reason: nodeCode(error) === "ENOENT" ? "missing" : error instanceof TypeError || error instanceof SyntaxError ? "corrupt" : "io",
        diagnostic: "Original execution output could not be verified or read." });
    }
  }
  async #control(executionId: string, command: ControlCommand): Promise<void> {
    this.#ensureOpen(); validateExecutionId(executionId);
    const directory = executionDirectory(this.root, executionId);
    const record = await readRecord(directory, executionId);
    if (command.kind === "activate" && acceptedActivation(record, command)) return;
    if (command.kind === "terminate" && (record.phase === "settled" || record.phase === "rejected")) return;
    if (record.phase !== "prepared" && record.phase !== "activating" && record.phase !== "running") throw new Error("Execution has no live control authority.");
    if (command.kind === "activate" && (record.policyDigest !== command.policyDigest || record.executionDigest !== command.executionDigest)) {
      throw new Error("Activation digests do not match the exact prepared authority.");
    }
    try { await sendControl(record.endpoint, record.authToken, command); }
    catch (error) {
      if (!(error instanceof SandboxExecutionControlError)) throw error;
      const current = await readRecord(directory, executionId);
      const control = readControl(this.root, executionId);
      if (error.failure !== "authentication-rejected" && (error.failure !== "operation-rejected" || error.delivery === "unknown")) {
        if (control?.id === command.id && control.digest === digestRun(command) && control.status === "applied") return;
        if (command.kind === "activate" && acceptedActivation(current, command)) return;
        if (command.kind === "terminate" && (current.phase === "settled" || current.phase === "rejected")) return;
      }
      error.observation = await this.#observe(current, 0, 0);
      throw error;
    }
  }
  #ensureOpen(): void { if (this.#closed) throw new Error("Sandbox execution repository is closed."); }
}
function acceptedActivation(record: ExecutionRecord, command: ControlCommand): boolean {
  const authority = record.phase === "settled" ? record.result : record.phase === "activating" || record.phase === "running" ? record : undefined;
  return authority !== undefined && authority.policyDigest === command.policyDigest && authority.executionDigest === command.executionDigest;
}
function isFinal(record: ExecutionRecord): record is Extract<ExecutionRecord, { phase: "settled" | "rejected" | "retired" }> {
  return record.phase === "settled" || record.phase === "rejected" || record.phase === "retired";
}
function storageObservation(executionId: string, error: unknown, requestDigest?: string): SandboxExecutionObservation {
  const missing = nodeCode(error) === "EXECUTION_NOT_FOUND";
  const sqliteCode = typeof error === "object" && error !== null && "errcode" in error && typeof error.errcode === "number" ? error.errcode & 0xff : 0;
  const corrupt = error instanceof TypeError || error instanceof SyntaxError || sqliteCode === 11 || sqliteCode === 26;
  return Object.freeze({ kind: "unknown", executionId, ...(requestDigest === undefined ? {} : { requestDigest }),
    reason: missing ? "not-found" : corrupt ? "corrupt-record" : "storage-unavailable",
    diagnostic: missing ? "No execution record exists for this identity." : corrupt ? "Stored execution evidence is incompatible or failed integrity validation." : "Committed execution state could not be read.",
    output: NO_OUTPUT });
}
function emptyBoundary() { return { finalCursor: 0, outputHash: ZERO_HASH, stdoutBytes: 0, stderrBytes: 0, omittedStdoutBytes: 0, omittedStderrBytes: 0 }; }
function validateDigest(value: unknown): asserts value is string {
  if (typeof value !== "string" || !/^(?:[a-z0-9_-]+:)?[a-f0-9]{64}$/u.test(value)) throw new TypeError("An exact authority digest is required.");
}
function validateQuery(query: SandboxExecutionQuery) {
  if (typeof query !== "object" || query === null || Array.isArray(query)) throw new TypeError("Execution query must be an object.");
  const afterCursor = nonnegative(query.afterCursor ?? 0, "afterCursor");
  const maxBytes = nonnegative(query.maxBytes ?? 0, "maxBytes");
  const waitMs = nonnegative(query.waitMs ?? 0, "waitMs");
  if (maxBytes > 1024 * 1024 || waitMs > 30_000) throw new RangeError("Execution query exceeds the 1 MiB / 30 second bound.");
  return { afterCursor, maxBytes, waitMs };
}
function positive(value: number, label: string): number { if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(label + " must be a positive safe integer."); return value; }
function nonnegative(value: number, label: string): number { if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(label + " must be a non-negative safe integer."); return value; }
function sleep(ms: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, ms)); }
function workerAlive(pid: number): boolean {
  if (pid === 0) return false;
  try { process.kill(pid, 0); return true; } catch (error) { return nodeCode(error) !== "ESRCH"; }
}
