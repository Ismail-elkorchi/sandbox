import { Buffer } from "node:buffer";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, readFile, realpath, rename, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { SandboxErrorData } from "./errors.js";
import type { EnforcementReport } from "./enforcement.js";
import type { SandboxDetachedRunOptions, SandboxExecutionOutputChunk } from "./execution.js";
import type { SandboxRunResult } from "./result.js";
import type { PreparedRunSummary } from "./summary.js";
import { parseCleanup, parseEnforcement, parseErrorData, parseRunSummary, parseViolation } from "./validation.js";

export const EXECUTION_SCHEMA_VERSION = 1;
export const STATE_FILE = "state.json";
export const OUTPUT_FILE = "output.jsonl";
export const RECEIPT_FILE = "receipt.json";
export const MAX_CONTROL_BYTES = 1024 * 1024;

export interface ExecutionRepositoryLimits {
  completedRetentionMs: number;
  expiredIdentityRetentionMs: number;
  maxRetainedOutputBytes: number;
  startupTimeoutMs: number;
}

export type ExecutionRecord =
  | ExecutionPreparingRecord
  | ExecutionPreparedRecord
  | ExecutionRunningRecord
  | ExecutionSettledRecord
  | ExecutionRejectedRecord
  | ExecutionUnknownRecord
  | ExecutionExpiredRecord;

interface ExecutionRecordBase {
  schemaVersion: 1;
  executionId: string;
  requestDigest: string;
  createdAtMs: number;
  workerPid: number;
  authToken: string;
  endpoint?: number;
}

export interface ExecutionPreparingRecord extends ExecutionRecordBase {
  phase: "preparing";
}

export interface ExecutionPreparedRecord extends ExecutionRecordBase {
  phase: "prepared";
  endpoint: number;
  policyDigest: string;
  executionDigest: string;
  summary: PreparedRunSummary;
  enforcement: EnforcementReport;
  expiresAtMs: number;
}

export interface ExecutionRunningRecord extends ExecutionRecordBase {
  phase: "running";
  endpoint: number;
  processId: string;
}

export interface ExecutionSettledRecord extends ExecutionRecordBase {
  phase: "settled";
  endpoint: number;
  processId: string;
  settledAtMs: number;
  expiresAtMs: number;
  cursorEnd: number;
  outputHash: string;
}

export interface ExecutionRejectedRecord extends ExecutionRecordBase {
  phase: "rejected";
  endpoint: number;
  rejectedAtMs: number;
  expiresAtMs: number;
  error: SandboxErrorData;
}

export interface ExecutionUnknownRecord extends ExecutionRecordBase {
  phase: "unknown";
  endpoint: number;
  unknownAtMs: number;
  reason: "execution-host-failed";
  diagnostic: string;
}

export interface ExecutionExpiredRecord {
  schemaVersion: 1;
  phase: "expired";
  executionId: string;
  requestDigest: string;
  createdAtMs: number;
  expiredAtMs: number;
}

interface StoredEnvelope {
  schemaVersion: 1;
  sha256: string;
  value: unknown;
}

interface StoredReceipt {
  result: Omit<SandboxRunResult, "stdout" | "stderr"> & {
    stdoutBase64?: string;
    stderrBase64?: string;
  };
}

interface StoredOutputChunk {
  sequence: number;
  cursorStart: number;
  cursorEnd: number;
  stream: "stdout" | "stderr";
  dataBase64: string;
  previousHash: string;
  hash: string;
}

export async function adoptExecutionRepositoryRoot(directory: string): Promise<string> {
  if (typeof directory !== "string" || directory.length === 0) throw new TypeError("Execution repository directory is required.");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new TypeError("Execution repository must be a non-symbolic directory.");
  if (process.platform !== "win32") {
    if ((metadata.mode & 0o077) !== 0) await chmod(directory, 0o700);
    const secured = await lstat(directory);
    if ((secured.mode & 0o077) !== 0) throw new TypeError("Execution repository permissions must exclude group and other users.");
  }
  return realpath(directory);
}

export function executionDirectory(root: string, executionId: string): string {
  return join(root, `execution-${createHash("sha256").update(executionId).digest("hex")}`);
}

export function validateExecutionId(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || value.trim() !== value) {
    throw new TypeError("Execution ID must be a non-empty, trimmed string of at most 256 characters.");
  }
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code !== undefined && (code <= 0x1f || code === 0x7f)) throw new TypeError("Execution ID must not contain control characters.");
  }
}

export function normalizeLimits(options: {
  completedRetentionMs?: number;
  expiredIdentityRetentionMs?: number;
  maxRetainedOutputBytes?: number;
  startupTimeoutMs?: number;
}): ExecutionRepositoryLimits {
  return {
    completedRetentionMs: positive(options.completedRetentionMs ?? 15 * 60_000, "completedRetentionMs"),
    expiredIdentityRetentionMs: positive(options.expiredIdentityRetentionMs ?? 60 * 60_000, "expiredIdentityRetentionMs"),
    maxRetainedOutputBytes: positive(options.maxRetainedOutputBytes ?? 16 * 1024 * 1024, "maxRetainedOutputBytes"),
    startupTimeoutMs: positive(options.startupTimeoutMs ?? 10_000, "startupTimeoutMs"),
  };
}

export function validateDetachedRun(value: SandboxDetachedRunOptions, maxRetainedOutputBytes: number): void {
  if (typeof value !== "object" || value === null) throw new TypeError("Detached sandbox run must be an object.");
  if (value.isolation?.kind !== "process") throw new TypeError("Detached execution supports process isolation only.");
  const limit = value.process?.resources?.maxOutputBytes ?? value.resources?.maxOutputBytes;
  if (!Number.isSafeInteger(limit) || (limit ?? 0) < 1) throw new TypeError("Detached execution requires a positive maxOutputBytes resource limit.");
  if ((limit as number) > maxRetainedOutputBytes) {
    throw new RangeError("Sandbox maxOutputBytes exceeds the execution repository output retention bound.");
  }
  rejectSignal(value, "run");
  rejectSignal(value.process, "process");
}

function rejectSignal(value: object, label: string): void {
  if ("signal" in value) throw new TypeError(`Detached ${label} options must not contain a process-local AbortSignal.`);
}

export function digestRun(value: SandboxDetachedRunOptions): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

export function repositoryIdentity(root: string): string {
  return `sandbox-execution-repository:sha256:${createHash("sha256").update(root).digest("hex")}`;
}

export function authToken(): string {
  return randomBytes(32).toString("hex");
}

export async function createExecutionDirectory(directory: string): Promise<boolean> {
  try {
    await mkdir(directory, { mode: 0o700 });
    return true;
  } catch (error) {
    if (nodeCode(error) === "EEXIST") return false;
    throw error;
  }
}

export async function writeRecord(directory: string, record: ExecutionRecord): Promise<void> {
  await writeEnvelope(join(directory, STATE_FILE), record);
}

export async function readRecord(directory: string): Promise<ExecutionRecord> {
  return parseRecord(await readEnvelope(join(directory, STATE_FILE)));
}

export async function writeReceipt(directory: string, result: SandboxRunResult): Promise<void> {
  const { stdout, stderr, ...fields } = result;
  const stored: StoredReceipt = {
    result: {
      ...fields,
      ...(stdout === undefined ? {} : { stdoutBase64: stdout.toString("base64") }),
      ...(stderr === undefined ? {} : { stderrBase64: stderr.toString("base64") }),
    },
  };
  await writeEnvelope(join(directory, RECEIPT_FILE), stored);
}

export async function readReceipt(directory: string): Promise<SandboxRunResult> {
  const source = record(await readEnvelope(join(directory, RECEIPT_FILE)), "execution receipt");
  const stored = record(source.result, "execution result");
  const value = { ...stored };
  const stdoutBase64 = optionalString(value.stdoutBase64, "stdoutBase64");
  const stderrBase64 = optionalString(value.stderrBase64, "stderrBase64");
  delete value.stdoutBase64;
  delete value.stderrBase64;
  return parseStoredRunResult(value, stdoutBase64, stderrBase64);
}

export async function appendOutput(
  directory: string,
  chunk: Omit<StoredOutputChunk, "hash">,
): Promise<string> {
  const unsigned = canonicalJson(chunk);
  const hash = createHash("sha256").update(unsigned).digest("hex");
  const line = `${JSON.stringify({ ...chunk, hash })}\n`;
  const file = await open(join(directory, OUTPUT_FILE), constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    await file.write(line);
    await file.sync();
  } finally {
    await file.close();
  }
  return hash;
}

export async function readOutput(
  directory: string,
  afterCursor: number,
  maxBytes: number,
  expectedEnd?: number,
  expectedHash?: string,
): Promise<{ cursorStart: number; cursorEnd: number; availableCursorEnd: number; stdoutBytes: number; stderrBytes: number; cursorExpired: boolean; chunks: readonly SandboxExecutionOutputChunk[] }> {
  let text = "";
  try {
    text = await readFile(join(directory, OUTPUT_FILE), "utf8");
  } catch (error) {
    if (nodeCode(error) !== "ENOENT") throw error;
  }
  const lines = text.split("\n");
  const completeLines = lines.at(-1) === "" ? lines.slice(0, -1) : lines.slice(0, -1);
  let previousHash = "0".repeat(64);
  let cursorEnd = 0;
  let stdoutBytes = 0;
  let stderrBytes = 0;
  const stored: StoredOutputChunk[] = [];
  for (const [index, line] of completeLines.entries()) {
    if (line.length === 0) continue;
    const chunk = parseOutputChunk(JSON.parse(line), index + 1);
    if (chunk.previousHash !== previousHash || chunk.cursorStart !== cursorEnd) throw new Error("Execution output hash chain is invalid.");
    const unsigned = { ...chunk } as Record<string, unknown>;
    delete unsigned.hash;
    if (createHash("sha256").update(canonicalJson(unsigned)).digest("hex") !== chunk.hash) throw new Error("Execution output chunk checksum is invalid.");
    previousHash = chunk.hash;
    cursorEnd = chunk.cursorEnd;
    if (chunk.stream === "stdout") stdoutBytes += chunk.cursorEnd - chunk.cursorStart;
    else stderrBytes += chunk.cursorEnd - chunk.cursorStart;
    stored.push(chunk);
  }
  if (expectedEnd !== undefined && (cursorEnd !== expectedEnd || previousHash !== expectedHash)) {
    throw new Error("Execution output does not match its terminal receipt.");
  }
  if (!Number.isSafeInteger(afterCursor) || afterCursor < 0 || afterCursor > cursorEnd) throw new RangeError("Invalid execution output cursor.");
  let remaining = positive(maxBytes, "maxBytes");
  const chunks: SandboxExecutionOutputChunk[] = [];
  let cursorStart = afterCursor;
  for (const item of stored) {
    if (item.cursorEnd <= afterCursor || remaining === 0) continue;
    const data = Buffer.from(item.dataBase64, "base64");
    const offset = Math.max(0, afterCursor - item.cursorStart);
    const selected = data.subarray(offset, offset + remaining);
    if (selected.byteLength === 0) continue;
    const start = item.cursorStart + offset;
    chunks.push(Object.freeze({ cursorStart: start, cursorEnd: start + selected.byteLength, stream: item.stream, data: Buffer.from(selected) }));
    if (chunks.length === 1) cursorStart = start;
    remaining -= selected.byteLength;
  }
  const observedEnd = chunks.at(-1)?.cursorEnd ?? afterCursor;
  return Object.freeze({ cursorStart, cursorEnd: observedEnd, availableCursorEnd: cursorEnd, stdoutBytes, stderrBytes, cursorExpired: false, chunks: Object.freeze(chunks) });
}

export async function expireRecord(directory: string, recordValue: ExecutionSettledRecord | ExecutionRejectedRecord): Promise<void> {
  const lock = join(directory, "expire.lock");
  let handle;
  try {
    handle = await open(lock, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  } catch (error) {
    if (nodeCode(error) === "EEXIST") return;
    throw error;
  }
  try {
    await rm(join(directory, OUTPUT_FILE), { force: true });
    await rm(join(directory, RECEIPT_FILE), { force: true });
    await writeRecord(directory, {
      schemaVersion: 1,
      phase: "expired",
      executionId: recordValue.executionId,
      requestDigest: recordValue.requestDigest,
      createdAtMs: recordValue.createdAtMs,
      expiredAtMs: recordValue.expiresAtMs,
    });
  } finally {
    await handle.close();
    await rm(lock, { force: true });
  }
}

export async function removeExecutionDirectory(directory: string): Promise<void> {
  await rm(directory, { recursive: true, force: true });
}

export function serializeRunForHost(run: SandboxDetachedRunOptions, limits: ExecutionRepositoryLimits): string {
  return JSON.stringify({ schemaVersion: 1, run, limits });
}

export function parseRunForHost(value: unknown): { run: SandboxDetachedRunOptions; limits: ExecutionRepositoryLimits } {
  const source = record(value, "execution host request");
  if (source.schemaVersion !== 1) throw new TypeError("Unsupported execution host request schema.");
  const limits = record(source.limits, "execution repository limits");
  const parsedLimits = normalizeLimits({
    completedRetentionMs: requiredNumber(limits.completedRetentionMs, "completedRetentionMs"),
    expiredIdentityRetentionMs: requiredNumber(limits.expiredIdentityRetentionMs, "expiredIdentityRetentionMs"),
    maxRetainedOutputBytes: requiredNumber(limits.maxRetainedOutputBytes, "maxRetainedOutputBytes"),
    startupTimeoutMs: requiredNumber(limits.startupTimeoutMs, "startupTimeoutMs"),
  });
  const run = source.run as SandboxDetachedRunOptions;
  validateDetachedRun(run, parsedLimits.maxRetainedOutputBytes);
  return { run, limits: parsedLimits };
}

export function sandboxErrorData(error: unknown, targetExecuted: boolean): SandboxErrorData {
  if (typeof error === "object" && error !== null && "data" in error) {
    try {
      return parseErrorData((error as { data: unknown }).data);
    } catch {
      // Fall through to the bounded host error below.
    }
  }
  return {
    code: targetExecuted ? "runtime_crashed.detached_host" : "spawn.detached_host",
    message: bounded(error instanceof Error ? error.message : String(error)),
    phase: targetExecuted ? "execute" : "spawn",
    targetExecuted,
  };
}

export function randomTempName(path: string): string {
  return `${path}.${process.pid}.${randomUUID()}.tmp`;
}

async function writeEnvelope(path: string, value: unknown): Promise<void> {
  const serializedValue = canonicalJson(value);
  const envelope: StoredEnvelope = {
    schemaVersion: 1,
    sha256: createHash("sha256").update(serializedValue).digest("hex"),
    value,
  };
  const temporary = randomTempName(path);
  const file = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    await file.writeFile(`${JSON.stringify(envelope)}\n`, "utf8");
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(temporary, path);
  const directory = await open(dirname(path), constants.O_RDONLY);
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

async function readEnvelope(path: string): Promise<unknown> {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let text: string;
  try {
    text = await file.readFile("utf8");
  } finally {
    await file.close();
  }
  const envelope = record(JSON.parse(text), "stored execution envelope");
  if (envelope.schemaVersion !== 1) throw new TypeError("Unsupported stored execution envelope schema.");
  const checksum = requiredString(envelope.sha256, "stored execution checksum");
  if (createHash("sha256").update(canonicalJson(envelope.value)).digest("hex") !== checksum) {
    throw new TypeError("Stored execution envelope checksum is invalid.");
  }
  return envelope.value;
}

function parseRecord(value: unknown): ExecutionRecord {
  const source = record(value, "execution record");
  if (source.schemaVersion !== 1) throw new TypeError("Unsupported execution record schema.");
  const phase = requiredString(source.phase, "execution phase");
  const base = {
    schemaVersion: 1 as const,
    executionId: requiredString(source.executionId, "execution ID"),
    requestDigest: requiredString(source.requestDigest, "request digest"),
    createdAtMs: requiredNumber(source.createdAtMs, "execution creation time"),
  };
  if (phase === "expired") return { ...base, phase, expiredAtMs: requiredNumber(source.expiredAtMs, "expiration time") };
  const live = {
    ...base,
    workerPid: requiredNumber(source.workerPid, "worker PID"),
    authToken: requiredString(source.authToken, "execution auth token"),
  };
  if (phase === "preparing") return { ...live, phase };
  const endpoint = requiredNumber(source.endpoint, "execution endpoint");
  if (phase === "prepared") return {
    ...live, phase, endpoint,
    policyDigest: digestString(source.policyDigest, "policy digest"),
    executionDigest: digestString(source.executionDigest, "execution digest"),
    summary: parseRunSummary(source.summary),
    enforcement: parseEnforcement(source.enforcement),
    expiresAtMs: requiredNumber(source.expiresAtMs, "preparation expiration"),
  };
  if (phase === "running") return { ...live, phase, endpoint, processId: requiredString(source.processId, "process ID") };
  if (phase === "settled") return {
    ...live, phase, endpoint, processId: requiredString(source.processId, "process ID"),
    settledAtMs: requiredNumber(source.settledAtMs, "settlement time"),
    expiresAtMs: requiredNumber(source.expiresAtMs, "receipt expiration"),
    cursorEnd: requiredNumber(source.cursorEnd, "output cursor"),
    outputHash: requiredString(source.outputHash, "output hash"),
  };
  if (phase === "rejected") return {
    ...live, phase, endpoint,
    rejectedAtMs: requiredNumber(source.rejectedAtMs, "rejection time"),
    expiresAtMs: requiredNumber(source.expiresAtMs, "receipt expiration"),
    error: parseErrorData(source.error),
  };
  if (phase === "unknown") return {
    ...live, phase, endpoint,
    unknownAtMs: requiredNumber(source.unknownAtMs, "unknown outcome time"),
    reason: source.reason === "execution-host-failed" ? source.reason : fail("Invalid unknown outcome reason."),
    diagnostic: requiredString(source.diagnostic, "unknown outcome diagnostic"),
  };
  throw new TypeError(`Unknown execution record phase: ${phase}`);
}

function parseOutputChunk(value: unknown, sequence: number): StoredOutputChunk {
  const source = record(value, `output chunk ${sequence}`);
  const parsed: StoredOutputChunk = {
    sequence: requiredNumber(source.sequence, "output sequence"),
    cursorStart: requiredNumber(source.cursorStart, "output cursor start"),
    cursorEnd: requiredNumber(source.cursorEnd, "output cursor end"),
    stream: source.stream === "stdout" || source.stream === "stderr" ? source.stream : fail("Invalid output stream."),
    dataBase64: requiredString(source.dataBase64, "output data"),
    previousHash: requiredString(source.previousHash, "previous output hash"),
    hash: requiredString(source.hash, "output hash"),
  };
  if (parsed.sequence !== sequence || parsed.cursorEnd < parsed.cursorStart || Buffer.from(parsed.dataBase64, "base64").byteLength !== parsed.cursorEnd - parsed.cursorStart) {
    throw new TypeError("Execution output chunk geometry is invalid.");
  }
  return parsed;
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
  stdoutBase64: string | undefined,
  stderrBase64: string | undefined,
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
    ...(stdoutBase64 === undefined ? {} : { stdout: Buffer.from(stdoutBase64, "base64") }),
    ...(stderrBase64 === undefined ? {} : { stderr: Buffer.from(stderrBase64, "base64") }),
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
    path: requiredString(source.path, "artifact path"),
    kind,
    mode: requiredNumber(source.mode, "artifact mode"),
    modifiedUnixMs: requiredNumber(source.modifiedUnixMs, "artifact modified time"),
    ...(source.contentHex === undefined ? {} : { contentHex: requiredString(source.contentHex, "artifact content") }),
    ...(source.linkTarget === undefined ? {} : { linkTarget: requiredString(source.linkTarget, "artifact link target") }),
    ...(source.sha256 === undefined ? {} : { sha256: digestString(source.sha256, "artifact digest") }),
  };
}

function parseStoredWorkspaceChangeSet(value: unknown): NonNullable<SandboxRunResult["changeSets"]>[number] {
  const source = record(value, "workspace change set");
  const change = record(source.changeSet, "change set");
  if (change.formatVersion !== 1) throw new TypeError("Unsupported change-set format version.");
  return {
    targetPath: requiredString(source.targetPath, "change-set target path"),
    bytes: requiredNumber(source.bytes, "change-set bytes"),
    changeSet: {
      formatVersion: 1,
      baseManifestDigest: digestString(change.baseManifestDigest, "change-set base digest"),
      digest: digestString(change.digest, "change-set digest"),
      base: array(change.base, "change-set base").map((entry) => {
        const parsed = parseStoredArtifactEntry(entry);
        return parsed;
      }),
      operations: array(change.operations, "change-set operations").map((operation) => {
        const item = record(operation, "change-set operation");
        if (item.kind === "upsert") return { kind: "upsert" as const, entry: parseStoredArtifactEntry(item.entry) };
        if (item.kind === "delete") return { kind: "delete" as const, path: requiredString(item.path, "deleted path") };
        if (item.kind === "rename") return { kind: "rename" as const, from: requiredString(item.from, "renamed source"), to: requiredString(item.to, "renamed target") };
        throw new TypeError("Invalid stored change-set operation.");
      }),
    },
  };
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

function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  return requiredString(value, label);
}

function requiredNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} must be a non-negative safe integer.`);
  return value;
}

function positive(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${label} must be a positive safe integer.`);
  return value;
}

function bounded(value: string): string {
  return value.length <= 4096 ? value : `${value.slice(0, 4093)}...`;
}

function fail(message: string): never {
  throw new TypeError(message);
}

function nodeCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" ? error.code : undefined;
}
