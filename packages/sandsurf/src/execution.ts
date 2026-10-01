import { SandsurfHostError, integer, record, text } from "./native-host.js";
import { sandsurfDigest, validateExecutionRequest, validateSandsurfOutputBoundary } from "./sandsurf-protocol.js";
import type { ExecutionRequest, OutputBoundary } from "./sandsurf-protocol.js";

/** Guest-reported outcome. Even an authenticated report is not host attestation. */
export type ExecutionOutcome =
  | { readonly kind: "exit"; readonly code: number }
  | { readonly kind: "signal"; readonly signal: number }
  | { readonly kind: "deadline-exceeded" }
  | { readonly kind: "spawn-failed"; readonly reason: string }
  | { readonly kind: "interrupted"; readonly evidence: string };
export type ExecutionState =
  | { readonly kind: "running" }
  | { readonly kind: "draining"; readonly outcome: ExecutionOutcome; readonly accountingDigest: string }
  | { readonly kind: "exited"; readonly outcome: ExecutionOutcome; readonly output: OutputBoundary; readonly cleanupDigest: string; readonly accountingDigest: string }
  | { readonly kind: "unknown"; readonly evidence: string };
export interface ExecutionLineage {
  readonly logicalExecutionId: string;
  readonly sourceExecutionId: string;
  readonly sourceMachineId: string;
  readonly sourceGeneration: number;
  readonly snapshotId: string;
  readonly outputAnchor: OutputBoundary;
}
export interface ExecutionInspection {
  readonly request: ExecutionRequest;
  readonly guestPid: number;
  readonly state: ExecutionState;
  readonly lineage: ExecutionLineage | null;
}
export interface Receipt {
  readonly machineId: string; readonly generation: number; readonly executionId: string;
  readonly operationId: string; readonly requestDigest: string;
  readonly outcome: ExecutionOutcome; readonly output: OutputBoundary;
  readonly cleanupDigest: string; readonly accountingDigest: string;
}

function invalid(): never { throw new SandsurfHostError("protocol", "Invalid execution observation"); }
function object(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!record(value) || keys.some((key) => !Object.hasOwn(value, key)) || Object.keys(value).some((key) => !keys.includes(key))) invalid();
  return value;
}
function hash(value: unknown): string { const result = text(value); if (!/^[a-f0-9]{64}$/u.test(result)) invalid(); return result; }
function id(value: unknown): string { const result = text(value); if (!/^[A-Za-z0-9_-]{1,128}$/u.test(result)) invalid(); return result; }
function positive(value: unknown): number { const result = integer(value); if (result < 1) invalid(); return result; }
function boundary(value: unknown): OutputBoundary {
  try { validateSandsurfOutputBoundary(value); } catch { invalid(); }
  return { ...value };
}
export function parseExecutionRequest(value: unknown): ExecutionRequest {
  try { validateExecutionRequest(value); } catch { invalid(); }
  return { ...value, argv: [...value.argv], environment: { ...value.environment }, terminalSize: value.terminalSize === null ? null : { ...value.terminalSize } };
}
export function parseExecutionOutcome(value: unknown): ExecutionOutcome {
  if (!record(value)) invalid();
  switch (value.kind) {
    case "exit": {
      const result = object(value, ["kind", "code"]);
      if (typeof result.code !== "number" || !Number.isInteger(result.code) || result.code < -2147483648 || result.code > 2147483647) invalid();
      return { kind: "exit", code: result.code };
    }
    case "signal": {
      const result = object(value, ["kind", "signal"]); const signal = integer(result.signal);
      if (signal < 1 || signal > 0xffffffff) invalid(); return { kind: "signal", signal };
    }
    case "deadline-exceeded": object(value, ["kind"]); return { kind: "deadline-exceeded" };
    case "spawn-failed": object(value, ["kind", "reason"]); return { kind: "spawn-failed", reason: hash(value.reason) };
    case "interrupted": object(value, ["kind", "evidence"]); return { kind: "interrupted", evidence: hash(value.evidence) };
    default: invalid();
  }
}
export function parseExecutionState(value: unknown): ExecutionState {
  if (!record(value)) invalid();
  switch (value.kind) {
    case "running": object(value, ["kind"]); return { kind: "running" };
    case "draining": object(value, ["kind", "outcome", "accountingDigest"]);
      return { kind: "draining", outcome: parseExecutionOutcome(value.outcome), accountingDigest: hash(value.accountingDigest) };
    case "exited": object(value, ["kind", "outcome", "output", "cleanupDigest", "accountingDigest"]);
      return { kind: "exited", outcome: parseExecutionOutcome(value.outcome), output: boundary(value.output), cleanupDigest: hash(value.cleanupDigest), accountingDigest: hash(value.accountingDigest) };
    case "unknown": object(value, ["kind", "evidence"]); return { kind: "unknown", evidence: hash(value.evidence) };
    default: invalid();
  }
}
export function parseExecutionInspection(value: unknown): ExecutionInspection {
  const result = object(value, ["request", "guestPid", "state", "lineage"]);
  const request = parseExecutionRequest(result.request); const guestPid = integer(result.guestPid);
  if (guestPid > 0xffffffff) invalid();
  const lineage = parseExecutionLineage(result.lineage, request);
  return { request, guestPid, state: parseExecutionState(result.state), lineage };
}
export function parseExecutionLineage(value: unknown, request: Pick<ExecutionRequest, "machineId" | "generation" | "executionId">): ExecutionLineage | null {
  if (value === null) return null;
  const origin = object(value, ["logicalExecutionId", "sourceExecutionId", "sourceMachineId", "sourceGeneration", "snapshotId", "outputAnchor"]);
  const lineage: ExecutionLineage = { logicalExecutionId: id(origin.logicalExecutionId), sourceExecutionId: id(origin.sourceExecutionId),
    sourceMachineId: id(origin.sourceMachineId), sourceGeneration: positive(origin.sourceGeneration), snapshotId: id(origin.snapshotId), outputAnchor: boundary(origin.outputAnchor) };
  if (lineage.sourceGeneration >= request.generation || lineage.sourceMachineId !== request.machineId || lineage.sourceExecutionId === request.executionId) invalid();
  return lineage;
}
export function parseExecutionReceipt(value: unknown, expectedDigest: string): Receipt {
  const result = object(value, ["machineId", "generation", "executionId", "operationId", "requestDigest", "outcome", "output", "cleanupDigest", "accountingDigest"]);
  const receipt: Receipt = { machineId: id(result.machineId), generation: positive(result.generation), executionId: id(result.executionId),
    operationId: id(result.operationId), requestDigest: hash(result.requestDigest), outcome: parseExecutionOutcome(result.outcome), output: boundary(result.output),
    cleanupDigest: hash(result.cleanupDigest), accountingDigest: hash(result.accountingDigest) };
  if (sandsurfDigest("receipt", receipt) !== hash(expectedDigest)) invalid();
  return receipt;
}
