import { SandsurfHostError, integer, text } from "./native-host.js";
import { sandsurfDigest, validateExecutionRequest, validateSandsurfOutputBoundary } from "./sandsurf-protocol.js";
import type { ExecutionRequest, OutputBoundary } from "./sandsurf-protocol.js";
import type { ExecutionOutcome, ExecutionState, ExecutionLineage, ExecutionSnapshot as ExecutionInspection, Receipt, ProtocolTypes } from "./protocol-generated.js";
import { validateProtocol } from "./protocol-validation.js";
export type { ExecutionOutcome, ExecutionState, ExecutionLineage, ExecutionSnapshot as ExecutionInspection, Receipt } from "./protocol-generated.js";

function invalid(): never { throw new SandsurfHostError("protocol", "Invalid execution observation"); }
function wire<K extends keyof ProtocolTypes>(name: K, value: unknown): ProtocolTypes[K] {
  try { validateProtocol(name, value); } catch { invalid(); }
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
  const result = wire("ExecutionOutcome", value);
  switch (result.kind) {
    case "exit": return { ...result };
    case "signal": if (result.signal < 1) invalid(); return { ...result };
    case "deadline-exceeded": return { ...result };
    case "spawn-failed": return { kind: result.kind, reason: hash(result.reason) };
    case "interrupted": return { kind: result.kind, evidence: hash(result.evidence) };
  }
}
export function parseExecutionState(value: unknown): ExecutionState {
  const result = wire("ExecutionState", value);
  switch (result.kind) {
    case "running": return { ...result };
    case "draining": return { kind: result.kind, outcome: parseExecutionOutcome(result.outcome), accountingDigest: hash(result.accountingDigest) };
    case "exited": return { kind: result.kind, outcome: parseExecutionOutcome(result.outcome), output: boundary(result.output), cleanupDigest: hash(result.cleanupDigest), accountingDigest: hash(result.accountingDigest) };
    case "unknown": return { kind: result.kind, evidence: hash(result.evidence) };
  }
}
export function parseExecutionInspection(value: unknown): ExecutionInspection {
  const result = wire("ExecutionSnapshot", value);
  const request = parseExecutionRequest(result.request);
  return { request, guestPid: result.guestPid, state: parseExecutionState(result.state), lineage: parseExecutionLineage(result.lineage, request) };
}
export function parseExecutionLineage(value: unknown, request: Pick<ExecutionRequest, "machineId" | "generation" | "executionId">): ExecutionLineage | null {
  if (value === null) return null;
  const origin = wire("ExecutionLineage", value);
  const lineage: ExecutionLineage = { logicalExecutionId: id(origin.logicalExecutionId), sourceExecutionId: id(origin.sourceExecutionId),
    sourceMachineId: id(origin.sourceMachineId), sourceGeneration: positive(origin.sourceGeneration), snapshotId: id(origin.snapshotId), outputAnchor: boundary(origin.outputAnchor) };
  if (lineage.sourceGeneration >= request.generation || lineage.sourceMachineId !== request.machineId || lineage.sourceExecutionId === request.executionId) invalid();
  return lineage;
}
export function parseExecutionReceipt(value: unknown, expectedDigest: string): Receipt {
  const result = wire("Receipt", value);
  const receipt: Receipt = { machineId: id(result.machineId), generation: positive(result.generation), executionId: id(result.executionId),
    operationId: id(result.operationId), requestDigest: hash(result.requestDigest), outcome: parseExecutionOutcome(result.outcome), output: boundary(result.output),
    cleanupDigest: hash(result.cleanupDigest), accountingDigest: hash(result.accountingDigest) };
  if (sandsurfDigest("receipt", receipt) !== hash(expectedDigest)) invalid();
  return receipt;
}
