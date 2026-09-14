import { Buffer } from "node:buffer";
import { createHash, randomBytes } from "node:crypto";
import { chmod, lstat, mkdir, realpath, rm } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import type { SandboxErrorData } from "./errors.js";
import type { EnforcementReport } from "./enforcement.js";
import type { SandboxDetachedRunOptions, SandboxExecutionPreparation, SandboxExecutionReceipt, SandboxExecutionRepositoryOptions } from "./execution.js";
import type { SandboxChangeArtifactEntry, SandboxRunResult } from "./result.js";
import type { PreparedRunSummary } from "./summary.js";
import { parseCleanup, parseEnforcement, parseErrorData, parseRunSummary, parseViolation } from "./validation.js";
import { BASE_RECORD_BYTES, initializeStorage, MAX_RECORD_BYTES, transaction, withStorage } from "./execution-storage.js";

export const OUTPUT_FILE = "output.jsonl";
export const ZERO_HASH = "0".repeat(64);
export const executionRecordReadMetrics = { records: 0, bytes: 0 };
export interface ExecutionRepositoryLimits {
  maxRetainedOutputBytes: number; maxTotalOutputBytes: number; maxTotalMetadataBytes: number;
  maxRetainedExecutions: number; maxRetainedIdentities: number; startupTimeoutMs: number;
}
interface ExecutionRecordBase {
  schemaVersion: 1; contract: "retained-execution"; executionId: string; requestDigest: string;
  createdAtMs: number; admitterPid: number; workerPid: number; authToken: string; outputLimit: number; metadataLimit: number; endpoint?: number;
  preparation?: SandboxExecutionPreparation;
}
export interface ExecutionPreparingRecord extends ExecutionRecordBase { phase: "preparing" }
export interface ExecutionPreparedRecord extends ExecutionRecordBase {
  phase: "prepared"; endpoint: number; policyDigest: string; executionDigest: string;
  summary: PreparedRunSummary; enforcement: EnforcementReport; expiresAtMs: number;
}
export interface ExecutionActivatingRecord extends ExecutionRecordBase {
  phase: "activating"; endpoint: number; policyDigest: string; executionDigest: string; activatedAtMs: number;
}
export interface ExecutionRunningRecord extends ExecutionRecordBase {
  phase: "running"; endpoint: number; policyDigest: string; executionDigest: string; processId: string;
}
export interface ExecutionSettledRecord extends ExecutionRecordBase {
  phase: "settled"; endpoint: number; settledAtMs: number;
  result: Omit<SandboxRunResult, "stdout" | "stderr">; receipt: SandboxExecutionReceipt;
}
export interface ExecutionRejectedRecord extends ExecutionRecordBase {
  phase: "rejected"; endpoint: number; rejectedAtMs: number; error: SandboxErrorData; receipt: SandboxExecutionReceipt;
}
export interface ExecutionUnknownRecord extends ExecutionRecordBase {
  phase: "unknown"; unknownAtMs: number; diagnostic: string;
}
export interface ExecutionRetiredRecord {
  schemaVersion: 1; contract: "retained-execution"; phase: "retired";
  executionId: string; requestDigest: string; createdAtMs: number;
  reason: "released" | "acknowledged-unknown"; receiptDigest?: string; cleanupPending: boolean;
}
export type ExecutionRecord = ExecutionPreparingRecord | ExecutionPreparedRecord | ExecutionActivatingRecord
  | ExecutionRunningRecord | ExecutionSettledRecord | ExecutionRejectedRecord | ExecutionUnknownRecord | ExecutionRetiredRecord;
export type TerminalRecord = ExecutionSettledRecord | ExecutionRejectedRecord;

export async function adoptExecutionRepositoryRoot(directory: string): Promise<string> {
  if (typeof directory !== "string" || directory.length === 0) throw new TypeError("Execution repository directory is required.");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new TypeError("Execution repository must be a non-symbolic directory.");
  if (process.platform !== "win32") {
    if ((metadata.mode & 0o077) !== 0) await chmod(directory, 0o700);
    if (((await lstat(directory)).mode & 0o077) !== 0) throw new TypeError("Execution repository permissions must exclude group and other users.");
  }
  return realpath(directory);
}
export function executionDirectory(root: string, executionId: string): string {
  return join(root, "execution-" + createHash("sha256").update(executionId).digest("hex"));
}
export function validateExecutionId(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || !value.isWellFormed() || value.trim() !== value || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError("Execution ID must be a non-empty, trimmed string of at most 256 characters without control characters.");
  }
}
export function normalizeLimits(options: SandboxExecutionRepositoryOptions): ExecutionRepositoryLimits {
  const allowed = new Set(["directory", "maxRetainedOutputBytes", "maxTotalOutputBytes", "maxTotalMetadataBytes", "maxRetainedExecutions", "maxRetainedIdentities", "startupTimeoutMs"]);
  for (const key of Object.keys(options)) if (!allowed.has(key)) throw new TypeError("Unsupported execution repository option.");
  const limits = {
    maxRetainedOutputBytes: positive(options.maxRetainedOutputBytes ?? 16 * 1024 * 1024, "maxRetainedOutputBytes"),
    maxTotalOutputBytes: positive(options.maxTotalOutputBytes ?? 1024 * 1024 * 1024, "maxTotalOutputBytes"),
    maxTotalMetadataBytes: positive(options.maxTotalMetadataBytes ?? 1024 * 1024 * 1024, "maxTotalMetadataBytes"),
    maxRetainedExecutions: positive(options.maxRetainedExecutions ?? 128, "maxRetainedExecutions"),
    maxRetainedIdentities: positive(options.maxRetainedIdentities ?? 16_384, "maxRetainedIdentities"),
    startupTimeoutMs: positive(options.startupTimeoutMs ?? 10_000, "startupTimeoutMs"),
  };
  if (limits.maxRetainedExecutions > limits.maxRetainedIdentities) throw new RangeError("Retained executions cannot exceed the identity bound.");
  if (limits.startupTimeoutMs > 30_000) throw new RangeError("Execution startup observation cannot exceed 30 seconds.");
  return limits;
}
export async function initializeRepository(root: string, limits: ExecutionRepositoryLimits): Promise<void> {
  const { startupTimeoutMs: _startup, ...storageLimits } = limits;
  await initializeStorage(root, storageLimits);
}
export function validateDetachedRun(value: SandboxDetachedRunOptions, maxRetainedOutputBytes: number): void {
  if (typeof value !== "object" || value === null) throw new TypeError("Detached sandbox run must be an object.");
  if (value.isolation?.kind !== "process") throw new TypeError("Detached execution supports process isolation only.");
  const limit = value.resources?.output;
  if (limit?.enforcement !== "hard" || limit.scope !== "process" || !Number.isSafeInteger(limit.value) || limit.value < 1) {
    throw new TypeError("Detached execution requires a positive process-scoped resources.output hard limit.");
  }
  if (limit.value > maxRetainedOutputBytes) throw new RangeError("Sandbox resources.output exceeds the execution repository output retention bound.");
  if (typeof value.process !== "object" || value.process === null) throw new TypeError("Detached process options are required.");
  if ("signal" in value || "signal" in value.process) throw new TypeError("Detached options must not contain a process-local AbortSignal.");
}
export function digestRun(value: unknown): string { return "sha256:" + createHash("sha256").update(canonicalJson(value)).digest("hex"); }
export function repositoryIdentity(root: string): string { return "sandbox-execution-repository:sha256:" + createHash("sha256").update(root).digest("hex"); }
export function authToken(): string { return randomBytes(32).toString("hex"); }

export function metadataReservation(run: SandboxDetachedRunOptions): number {
  let reserved = BASE_RECORD_BYTES;
  for (const request of [run.process.artifacts, run.process.changeSet]) {
    if (request === undefined) continue;
    const bytes = positive(request.maxBytes, "artifact/change-set maxBytes");
    if (bytes > 64 * 1024 * 1024) throw new RangeError("Artifact/change-set request exceeds its 64 MiB bound.");
    // Stored artifact content uses the existing hex representation. The base
    // allowance covers bounded native control messages and preparation evidence.
    reserved += 2 * bytes;
  }
  return reserved;
}

// Admission commits its reservations before a worker or output directory exists.
export function admitExecution(root: string, initial: ExecutionPreparingRecord, limits: ExecutionRepositoryLimits): boolean {
  const encoded = encodeRecord(initial);
  return withStorage(root, (db) => transaction(db, () => {
    const existing = db.prepare("SELECT request_digest FROM executions WHERE execution_id = ?").get(initial.executionId);
    if (existing !== undefined) {
      if (existing.request_digest !== initial.requestDigest) throw new Error("Execution identity is already bound to a different request.");
      return false;
    }
    const totals = db.prepare("SELECT count(*) AS identities, coalesce(sum(retained), 0) AS retained, coalesce(sum(reserved_bytes), 0) AS bytes, coalesce(sum(reserved_metadata), 0) AS metadata FROM executions").get()!;
    if (Number(totals.identities) >= limits.maxRetainedIdentities) throw new RangeError("Execution identity admission capacity is exhausted.");
    if (Number(totals.retained) >= limits.maxRetainedExecutions || initial.outputLimit > limits.maxTotalOutputBytes - Number(totals.bytes)
      || initial.metadataLimit > limits.maxTotalMetadataBytes - Number(totals.metadata)) {
      throw new RangeError("Execution retention admission capacity is exhausted.");
    }
    db.prepare("INSERT INTO executions (execution_id, request_digest, reserved_bytes, reserved_metadata, retained, state) VALUES (?, ?, ?, ?, 1, ?)")
      .run(initial.executionId, initial.requestDigest, initial.outputLimit, initial.metadataLimit, encoded);
    return true;
  }));
}
function checkDirectory(directory: string, executionId: string): void {
  if (basename(executionDirectory(dirname(directory), executionId)) !== basename(directory)) throw new TypeError("Execution record identity does not match its directory.");
}
export async function readRecord(directory: string, executionId: string): Promise<ExecutionRecord> {
  checkDirectory(directory, executionId);
  return withStorage(dirname(directory), (db) => {
    const row = db.prepare("SELECT state FROM executions WHERE execution_id = ?").get(executionId);
    if (row === undefined) throw Object.assign(new Error("No execution record exists for this identity."), { code: "EXECUTION_NOT_FOUND" });
    executionRecordReadMetrics.records++;
    executionRecordReadMetrics.bytes += Buffer.byteLength(requiredString(row.state, "execution state"));
    const parsed = decodeRecord(row.state);
    if (parsed.executionId !== executionId) throw new TypeError("Execution record identity mismatch.");
    return parsed;
  });
}
export async function writeRecord(directory: string, next: ExecutionRecord, expectedPhase?: ExecutionRecord["phase"]): Promise<void> {
  checkDirectory(directory, next.executionId);
  const encoded = encodeRecord(next);
  withStorage(dirname(directory), (db) => transaction(db, () => {
    const row = db.prepare("SELECT state FROM executions WHERE execution_id = ?").get(next.executionId);
    if (row === undefined) throw new Error("Execution must be admitted before publication.");
    const current = decodeRecord(row.state);
    if (current.requestDigest !== next.requestDigest) throw new Error("Execution request identity changed.");
    if (current.phase === "settled" || current.phase === "rejected" || current.phase === "retired") {
      if (digestRun(current) !== digestRun(next)) throw new Error("Committed terminal evidence is immutable.");
      return;
    }
    if (expectedPhase !== undefined && current.phase !== expectedPhase) throw new Error("Execution publication lost its expected state.");
    if (next.phase === "retired") throw new Error("Retirement requires an explicit release transaction.");
    if (current.authToken !== next.authToken || current.outputLimit !== next.outputLimit || current.metadataLimit !== next.metadataLimit || current.admitterPid !== next.admitterPid
      || current.createdAtMs !== next.createdAtMs || (current.workerPid !== 0 && current.workerPid !== next.workerPid)) {
      throw new Error("Execution publication changed its immutable admission authority.");
    }
    if (current.preparation !== undefined && digestRun(current.preparation) !== digestRun(next.preparation)) throw new Error("Execution preparation evidence changed.");
    const transitions: Record<typeof current.phase, readonly ExecutionRecord["phase"][]> = {
      preparing: ["preparing", "prepared", "rejected", "unknown"],
      prepared: ["activating", "rejected", "unknown"],
      activating: ["running", "rejected", "unknown"],
      running: ["settled", "unknown"],
      unknown: ["unknown"],
    };
    if (!transitions[current.phase].includes(next.phase)) throw new Error("Invalid execution state transition.");
    if (current.phase === "prepared" && next.phase === "activating"
      && (current.policyDigest !== next.policyDigest || current.executionDigest !== next.executionDigest)) throw new Error("Activation does not match prepared authority.");
    if (current.phase === "running" && next.phase === "settled" && current.processId !== next.result.processId) throw new Error("Terminal receipt process identity changed.");
    if (current.phase === "activating" || current.phase === "running") {
      const authority = next.phase === "settled" ? next.result : next;
      if (("policyDigest" in authority && (authority.policyDigest !== current.policyDigest || authority.executionDigest !== current.executionDigest))
        || (next.phase === "rejected" && current.phase === "running")) throw new Error("Execution publication does not match accepted authority.");
    }
    db.prepare("UPDATE executions SET state = ? WHERE execution_id = ?").run(encoded, next.executionId);
  }));
}
export function terminalReceipt<T extends Omit<TerminalRecord, "receipt">>(terminal: T, boundary: Omit<SandboxExecutionReceipt, "digest">): T & { receipt: SandboxExecutionReceipt } {
  return { ...terminal, receipt: { ...boundary, digest: digestRun({ terminal, boundary }) } };
}
export function retireExecution(root: string, executionId: string, expectedDigest: string | undefined, expectedUnknown?: ExecutionRecord): ExecutionRetiredRecord {
  return withStorage(root, (db) => transaction(db, () => {
    const row = db.prepare("SELECT state FROM executions WHERE execution_id = ?").get(executionId);
    if (row === undefined) throw new Error("Execution identity is not retained.");
    const current = decodeRecord(row.state);
    if (current.phase === "retired") {
      if (current.receiptDigest !== expectedDigest) throw new Error("Retirement receipt identity conflicts with the committed release.");
      return current;
    }
    if (expectedDigest !== undefined) {
      if (current.phase !== "settled" && current.phase !== "rejected") throw new Error("A live or uncertain execution cannot be forgotten.");
      if (current.receipt.digest !== expectedDigest) throw new Error("Terminal receipt identity does not match the authorized release.");
    } else if (expectedUnknown === undefined || encodeRecord(current) !== encodeRecord(expectedUnknown)) {
      throw new Error("Unknown outcome changed before acknowledgement.");
    }
    const retired: ExecutionRetiredRecord = {
      schemaVersion: 1, contract: "retained-execution", phase: "retired", executionId,
      requestDigest: current.requestDigest, createdAtMs: current.createdAtMs,
      reason: expectedDigest === undefined ? "acknowledged-unknown" : "released",
      ...(expectedDigest === undefined ? {} : { receiptDigest: expectedDigest }), cleanupPending: true,
    };
    // Reservation is released only after output deletion completes.
    db.prepare("UPDATE executions SET state = ?, control = NULL WHERE execution_id = ?").run(encodeRecord(retired), executionId);
    return retired;
  }));
}
export async function finishRetirement(root: string, retired: ExecutionRetiredRecord): Promise<void> {
  if (!retired.cleanupPending) return;
  await rm(executionDirectory(root, retired.executionId), { recursive: true, force: true });
  withStorage(root, (db) => transaction(db, () => {
    const current = decodeRecord(db.prepare("SELECT state FROM executions WHERE execution_id = ?").get(retired.executionId)?.state);
    if (current.phase !== "retired" || current.receiptDigest !== retired.receiptDigest) throw new Error("Retirement identity changed.");
    db.prepare("UPDATE executions SET state = ?, retained = 0, reserved_bytes = 0, reserved_metadata = 0 WHERE execution_id = ?")
      .run(encodeRecord({ ...current, cleanupPending: false }), retired.executionId);
  }));
}
export function inventory(root: string, afterCursor: number, limit: number): { sequence: number; executionId: string }[] {
  return withStorage(root, (db) => db.prepare("SELECT sequence, execution_id FROM executions WHERE sequence > ? ORDER BY sequence LIMIT ?")
    .all(afterCursor, limit).map((row) => ({ sequence: requiredNumber(row.sequence, "inventory sequence"), executionId: requiredString(row.execution_id, "inventory identity") })));
}
export interface StoredControl { id: string; digest: string; status: "accepted" | "applied" }
export function writeControl(root: string, executionId: string, control: StoredControl): void {
  withStorage(root, (db) => transaction(db, () => {
    const current = decodeRecord(db.prepare("SELECT state FROM executions WHERE execution_id = ?").get(executionId)?.state);
    if (current.phase === "retired") throw new Error("Execution is retired.");
    db.prepare("UPDATE executions SET control = ? WHERE execution_id = ?").run(JSON.stringify({ value: control, sha256: digestRun(control) }), executionId);
  }));
}
export function readControl(root: string, executionId: string): StoredControl | undefined {
  return withStorage(root, (db) => {
    const row = db.prepare("SELECT control FROM executions WHERE execution_id = ?").get(executionId);
    if (row?.control === null || row === undefined) return undefined;
    const envelope = record(JSON.parse(requiredString(row.control, "control receipt")), "control receipt envelope");
    if (envelope.sha256 !== digestRun(envelope.value)) throw new TypeError("Control receipt integrity binding is invalid.");
    const value = record(envelope.value, "control receipt");
    if (value.status !== "accepted" && value.status !== "applied") throw new TypeError("Invalid control receipt status.");
    return { id: requiredString(value.id, "control identity"), digest: digestString(value.digest, "control digest"), status: value.status };
  });
}
export function serializeRunForHost(run: SandboxDetachedRunOptions, limits: ExecutionRepositoryLimits): string {
  return JSON.stringify({ schemaVersion: 1, run, limits });
}
export function parseRunForHost(value: unknown): { run: SandboxDetachedRunOptions; limits: ExecutionRepositoryLimits } {
  const source = record(value, "execution host request");
  if (source.schemaVersion !== 1) throw new TypeError("Unsupported execution host request schema.");
  const parsedLimits = normalizeLimits({ ...record(source.limits, "execution repository limits"), directory: "" });
  const run = source.run as SandboxDetachedRunOptions;
  validateDetachedRun(run, parsedLimits.maxRetainedOutputBytes);
  return { run, limits: parsedLimits };
}
export function sandboxErrorData(error: unknown, targetExecuted: boolean): SandboxErrorData {
  if (typeof error === "object" && error !== null && "data" in error) {
    try { return parseErrorData(error.data); } catch { /* Keep raw protocol and secret data out of diagnostics. */ }
  }
  return { code: targetExecuted ? "runtime_crashed.detached_host" : "spawn.detached_host",
    message: "Detached execution host failed.", phase: targetExecuted ? "execute" : "spawn", targetExecuted };
}
function encodeRecord(value: ExecutionRecord): string {
  parseRecord(value);
  const text = JSON.stringify({ schemaVersion: 1, sha256: digestRun(value), value });
  if (Buffer.byteLength(text) > (value.phase === "retired" ? BASE_RECORD_BYTES : value.metadataLimit)) throw new RangeError("Execution metadata exceeds its reserved storage bound.");
  return text;
}
function decodeRecord(value: unknown): ExecutionRecord {
  const text = requiredString(value, "stored execution record");
  if (Buffer.byteLength(text) > MAX_RECORD_BYTES) throw new TypeError("Execution record exceeds its storage bound.");
  const envelope = record(JSON.parse(text), "stored execution envelope");
  if (envelope.schemaVersion !== 1 || envelope.sha256 !== digestRun(envelope.value)) throw new TypeError("Stored execution envelope checksum is invalid.");
  return parseRecord(envelope.value);
}
function parseRecord(value: unknown): ExecutionRecord {
  const source = record(value, "execution record");
  if (source.schemaVersion !== 1 || source.contract !== "retained-execution") throw new TypeError("Incompatible stored execution record.");
  const executionId = requiredString(source.executionId, "execution ID");
  validateExecutionId(executionId);
  const base = { schemaVersion: 1 as const, contract: "retained-execution" as const, executionId,
    requestDigest: digestString(source.requestDigest, "request digest"), createdAtMs: requiredNumber(source.createdAtMs, "creation time") };
  if (source.phase === "retired") {
    if (source.reason !== "released" && source.reason !== "acknowledged-unknown") throw new TypeError("Invalid retirement reason.");
    if (typeof source.cleanupPending !== "boolean") throw new TypeError("Invalid retirement cleanup state.");
    return { ...base, phase: "retired", reason: source.reason, cleanupPending: source.cleanupPending,
      ...(source.reason === "released" ? { receiptDigest: digestString(source.receiptDigest, "released receipt digest") } : {}) };
  }
  const live = { ...base, admitterPid: requiredNumber(source.admitterPid, "admitting process PID"), workerPid: requiredNumber(source.workerPid, "worker PID"),
    authToken: requiredString(source.authToken, "execution auth token"), outputLimit: positive(requiredNumber(source.outputLimit, "output limit"), "output limit"),
    metadataLimit: positive(requiredNumber(source.metadataLimit, "metadata limit"), "metadata limit"),
    ...(source.endpoint === undefined ? {} : { endpoint: requiredNumber(source.endpoint, "execution endpoint") }),
    ...(source.preparation === undefined ? {} : { preparation: parsePreparation(source.preparation) }) };
  if (!/^[a-f0-9]{64}$/u.test(live.authToken)) throw new TypeError("Invalid execution authentication authority.");
  if (live.metadataLimit < BASE_RECORD_BYTES || live.metadataLimit > MAX_RECORD_BYTES) throw new TypeError("Invalid execution metadata reservation.");
  if (live.endpoint !== undefined && live.endpoint > 65_535) throw new TypeError("Invalid execution endpoint.");
  if (source.phase === "preparing") return { ...live, phase: "preparing" };
  if (source.phase === "unknown") return { ...live, phase: "unknown", unknownAtMs: requiredNumber(source.unknownAtMs, "unknown time"), diagnostic: requiredString(source.diagnostic, "unknown diagnostic") };
  const endpoint = requiredNumber(source.endpoint, "endpoint");
  if (source.phase === "prepared") return { ...live, phase: "prepared", endpoint,
    policyDigest: digestString(source.policyDigest, "policy digest"), executionDigest: digestString(source.executionDigest, "execution digest"),
    summary: parseRunSummary(source.summary), enforcement: parseEnforcement(source.enforcement), expiresAtMs: requiredNumber(source.expiresAtMs, "preparation expiration") };
  if (source.phase === "activating" || source.phase === "running") {
    const authority = { ...live, endpoint, policyDigest: digestString(source.policyDigest, "policy digest"), executionDigest: digestString(source.executionDigest, "execution digest") };
    if (source.phase === "activating") return { ...authority, phase: "activating", activatedAtMs: requiredNumber(source.activatedAtMs, "activation time") };
    return { ...authority, phase: "running", processId: requiredString(source.processId, "process ID") };
  }
  if (source.phase === "settled" || source.phase === "rejected") {
    if ("expiresAtMs" in source) throw new TypeError("Incompatible terminal retention contract.");
    const receipt = record(source.receipt, "terminal receipt boundary");
    const boundary = {
      finalCursor: requiredNumber(receipt.finalCursor, "final cursor"), outputHash: digestString(receipt.outputHash, "output hash"),
      stdoutBytes: requiredNumber(receipt.stdoutBytes, "retained stdout bytes"), stderrBytes: requiredNumber(receipt.stderrBytes, "retained stderr bytes"),
      omittedStdoutBytes: requiredNumber(receipt.omittedStdoutBytes, "omitted stdout bytes"), omittedStderrBytes: requiredNumber(receipt.omittedStderrBytes, "omitted stderr bytes"),
    };
    if (boundary.stdoutBytes + boundary.stderrBytes !== boundary.finalCursor || boundary.finalCursor > live.outputLimit) throw new TypeError("Invalid terminal output boundary.");
    const terminal = source.phase === "settled"
      ? { ...live, endpoint, phase: "settled" as const, settledAtMs: requiredNumber(source.settledAtMs, "settlement time"), result: parseStoredRunResult(record(source.result, "terminal result")) }
      : { ...live, endpoint, phase: "rejected" as const, rejectedAtMs: requiredNumber(source.rejectedAtMs, "rejection time"), error: parseErrorData(source.error) };
    if (terminal.phase === "rejected" && terminal.error.targetExecuted) throw new TypeError("An executed effect cannot be rejected as unstarted.");
    if (terminal.phase === "settled" && (terminal.result.usage.stdoutBytes !== boundary.stdoutBytes + boundary.omittedStdoutBytes
      || terminal.result.usage.stderrBytes !== boundary.stderrBytes + boundary.omittedStderrBytes)) throw new TypeError("Terminal output accounting is inconsistent.");
    if (terminal.phase === "settled" && live.preparation !== undefined && (terminal.result.policyDigest !== live.preparation.policyDigest
      || terminal.result.executionDigest !== live.preparation.executionDigest)) throw new TypeError("Terminal result does not match preparation authority.");
    const digest = digestString(receipt.digest, "terminal receipt digest");
    if (digestRun({ terminal, boundary }) !== digest) throw new TypeError("Terminal receipt integrity binding is invalid.");
    return { ...terminal, receipt: { ...boundary, digest } };
  }
  throw new TypeError("Incompatible execution record phase.");
}

function parsePreparation(value: unknown): SandboxExecutionPreparation {
  const source = record(value, "preparation evidence");
  return { policyDigest: digestString(source.policyDigest, "policy digest"), executionDigest: digestString(source.executionDigest, "execution digest"),
    summary: parseRunSummary(source.summary), enforcement: parseEnforcement(source.enforcement), expiresAtMs: requiredNumber(source.expiresAtMs, "preparation expiration") };
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Execution request contains a non-finite number.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("Execution request must contain only plain data.");
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const entries: string[] = [];
    for (const key of Object.keys(descriptors).sort()) {
      const descriptor = descriptors[key];
      if (descriptor === undefined || descriptor.get !== undefined || descriptor.set !== undefined) throw new TypeError("Execution request must not contain accessors.");
      if (descriptor.value !== undefined) entries.push(`${JSON.stringify(key)}:${canonicalJson(descriptor.value)}`);
    }
    return `{${entries.join(",")}}`;
  }
  throw new TypeError("Execution request contains unsupported data.");
}

function parseStoredRunResult(
  source: Record<string, unknown>,
): SandboxRunResult {
  const result: SandboxRunResult = {
    processId: requiredString(source.processId, "result processId"),
    policyDigest: digestString(source.policyDigest, "result policyDigest"),
    executionDigest: digestString(source.executionDigest, "result executionDigest"),
    termination: parseStoredTermination(source.termination),
    enforcement: parseEnforcement(source.enforcement),
    violations: array(source.violations, "result violations").map(parseViolation),
    usage: parseStoredUsage(source.usage),
    cleanup: parseCleanup(source.cleanup),
  };
  if (source.artifacts !== undefined) result.artifacts = parseStoredArtifacts(source.artifacts);
  if (source.changeSets !== undefined) result.changeSets = array(source.changeSets, "result changeSets").map(parseStoredWorkspaceChangeSet);
  return result;
}

function parseStoredTermination(value: unknown): SandboxRunResult["termination"] {
  const source = record(value, "result termination");
  const reason = requiredString(source.reason, "termination reason");
  if (reason === "exit") return { reason, code: requiredNumber(source.code, "exit code") };
  if (reason === "signal") return { reason, signal: requiredString(source.signal, "termination signal") };
  if (reason === "policy-kill") return { reason, violation: parseViolation(source.violation) };
  if (reason === "runtime-failure") return { reason, error: parseErrorData(source.error) };
  if (reason === "timeout" || reason === "cancelled" || reason === "memory-limit" || reason === "cpu-limit"
    || reason === "process-limit" || reason === "output-limit" || reason === "single-file-size-limit") return { reason };
  throw new TypeError("Invalid stored sandbox termination.");
}

function parseStoredUsage(value: unknown): SandboxRunResult["usage"] {
  const source = record(value, "result usage");
  return {
    wallTimeMs: requiredNumber(source.wallTimeMs, "usage wallTimeMs"),
    stdoutBytes: requiredNumber(source.stdoutBytes, "usage stdoutBytes"),
    stderrBytes: requiredNumber(source.stderrBytes, "usage stderrBytes"),
    ...optionalNumberField(source, "cpuTimeMs"),
    ...optionalNumberField(source, "peakMemoryBytes"),
    ...optionalNumberField(source, "processesCreated"),
    ...optionalNumberField(source, "maxConcurrentProcesses"),
    ...optionalNumberField(source, "networkConnections"),
  };
}

function parseStoredArtifacts(value: unknown): NonNullable<SandboxRunResult["artifacts"]> {
  const source = record(value, "result artifacts");
  return {
    digest: digestString(source.digest, "artifact digest"),
    bytes: requiredNumber(source.bytes, "artifact bytes"),
    files: array(source.files, "artifact files").map(parseStoredArtifactEntry),
  };
}

function parseStoredArtifactEntry(value: unknown): NonNullable<SandboxRunResult["artifacts"]>["files"][number] {
  const source = record(value, "artifact entry");
  const kind = source.kind;
  if (kind !== "directory" && kind !== "regular-file" && kind !== "symbolic-link") throw new TypeError("Invalid artifact kind.");
  return {
    path: parseStoredPath(source.path, "artifact path"),
    kind,
    mode: requiredNumber(source.mode, "artifact mode"),
    modifiedUnixMs: requiredNumber(source.modifiedUnixMs, "artifact modified time"),
    ...(source.contentHex === undefined ? {} : { contentHex: requiredString(source.contentHex, "artifact content") }),
    ...(source.linkTarget === undefined ? {} : { linkTarget: requiredString(source.linkTarget, "artifact link target") }),
    ...(source.sha256 === undefined ? {} : { sha256: digestString(source.sha256, "artifact digest") }),
  };
}

function parseStoredChangeArtifactEntry(value: unknown): SandboxChangeArtifactEntry {
  const source = record(value, "change-set entry");
  const kind = source.kind;
  if (kind !== "directory" && kind !== "regular-file" && kind !== "symbolic-link") {
    throw new TypeError("Invalid change-set artifact kind.");
  }
  return {
    path: requiredString(source.path, "change-set artifact path"),
    kind,
    mode: requiredNumber(source.mode, "change-set artifact mode"),
    modifiedUnixMs: requiredNumber(source.modifiedUnixMs, "change-set artifact modified time"),
    ...(source.contentHex === undefined ? {} : { contentHex: requiredString(source.contentHex, "change-set artifact content") }),
    ...(source.linkTarget === undefined ? {} : { linkTarget: requiredString(source.linkTarget, "change-set artifact link target") }),
    ...(source.sha256 === undefined ? {} : { sha256: digestString(source.sha256, "change-set artifact digest") }),
  };
}

function parseStoredWorkspaceChangeSet(value: unknown): NonNullable<SandboxRunResult["changeSets"]>[number] {
  const source = record(value, "workspace change set");
  const change = record(source.changeSet, "change set");
  if (change.formatVersion !== 1) throw new TypeError("Unsupported change-set format version.");
  return {
    root: parseStoredPath(source.root, "change-set root"),
    bytes: requiredNumber(source.bytes, "change-set bytes"),
    changeSet: {
      formatVersion: 1,
      baseManifestDigest: digestString(change.baseManifestDigest, "change-set base digest"),
      digest: digestString(change.digest, "change-set digest"),
      base: array(change.base, "change-set base").map(parseStoredChangeArtifactEntry),
      operations: array(change.operations, "change-set operations").map((operation) => {
        const item = record(operation, "change-set operation");
        if (item.kind === "upsert") return { kind: "upsert" as const, entry: parseStoredChangeArtifactEntry(item.entry) };
        if (item.kind === "delete") return { kind: "delete" as const, path: requiredString(item.path, "deleted path") };
        if (item.kind === "rename") return { kind: "rename" as const, from: requiredString(item.from, "renamed source"), to: requiredString(item.to, "renamed target") };
        throw new TypeError("Invalid stored change-set operation.");
      }),
    },
  };
}

function parseStoredPath(value: unknown, label: string): import("./policy.js").SandboxPath {
  const source = record(value, label);
  const space = source.space;
  if (space !== "host" && space !== "isolated") throw new TypeError(`${label} has an invalid coordinate space.`);
  return { space, path: requiredString(source.path, `${label} path`) };
}

function optionalNumberField(source: Record<string, unknown>, key: string): Record<string, number> {
  return source[key] === undefined ? {} : { [key]: requiredNumber(source[key], `usage ${key}`) };
}

function digestString(value: unknown, label: string): string {
  const parsed = requiredString(value, label);
  if (!/^[a-z0-9_-]+:[a-f0-9]{64}$/u.test(parsed) && !/^[a-f0-9]{64}$/u.test(parsed)) throw new TypeError(`${label} is invalid.`);
  return parsed;
}

function array(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array.`);
  return value;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError(`${label} must be an object.`);
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`${label} must be a non-empty string.`);
  return value;
}


function requiredNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} must be a non-negative safe integer.`);
  return value;
}

function positive(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${label} must be a positive safe integer.`);
  return value;
}


function fail(message: string): never {
  throw new TypeError(message);
}
