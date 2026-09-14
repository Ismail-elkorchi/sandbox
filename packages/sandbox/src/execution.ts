import type { Buffer } from "node:buffer";
import type { SandboxErrorData } from "./errors.js";
import type { EnforcementReport } from "./enforcement.js";
import type { SandboxPolicy } from "./policy.js";
import type { SandboxArtifactRequest, SandboxWorkspaceChangeRequest } from "./process-options.js";
import type { SandboxPath } from "./policy.js";
import type { EnforcementRequirements } from "./requirements.js";
import type { ResourceLimits } from "./resources.js";
import type { SandboxRunResult } from "./result.js";
import type { PreparedRunSummary } from "./summary.js";

export interface SandboxExecutionRepositoryOptions {
  /** Private host directory that owns execution identities and retained receipts. */
  directory: string;
  /** Maximum output bytes retained for one execution. Must cover the requested sandbox output limit. */
  maxRetainedOutputBytes?: number;
  /** Aggregate reserved original output bytes. Defaults to 1 GiB. */
  maxTotalOutputBytes?: number;
  /** Aggregate reserved receipt/authority metadata, including artifact content. Defaults to 1 GiB. */
  maxTotalMetadataBytes?: number;
  /** Maximum executions retaining evidence or an unresolved outcome. Defaults to 128. */
  maxRetainedExecutions?: number;
  /** Includes compact retired identities, which prevent replay. Defaults to 16,384. */
  maxRetainedIdentities?: number;
  /** Maximum time allowed for the detached execution host to publish its control endpoint. */
  startupTimeoutMs?: number;
}

export interface SandboxExecutionRequest {
  /** Stable, caller-owned identity for exactly one logical external effect. */
  executionId: string;
  run: SandboxDetachedRunOptions;
}

export interface SandboxDetachedRunOptions {
  isolation: { kind: "process" };
  policy: SandboxPolicy;
  requirements: EnforcementRequirements;
  resources?: ResourceLimits;
  preparedTtlMs?: number;
  process: SandboxDetachedProcessOptions;
}

export interface SandboxDetachedProcessOptions {
  executable: SandboxPath;
  args?: readonly string[];
  cwd: SandboxPath;
  environment?: import("./environment.js").SandboxEnvironment;
  stdin?: "pipe" | "closed";
  stdout?: "pipe" | "capture" | "discard";
  stderr?: "pipe" | "capture" | "discard";
  artifacts?: SandboxArtifactRequest;
  changeSet?: SandboxWorkspaceChangeRequest;
}

export interface SandboxExecutionOutputChunk {
  cursorStart: number;
  cursorEnd: number;
  stream: "stdout" | "stderr";
  data: Buffer;
}

export interface SandboxExecutionAvailableOutput {
  kind: "available";
  cursorStart: number;
  /** Cursor immediately after the bytes returned by this observation. */
  cursorEnd: number;
  /** Cursor immediately after all output currently retained for the execution. */
  availableCursorEnd: number;
  stdoutBytes: number;
  stderrBytes: number;
  chunks: readonly SandboxExecutionOutputChunk[];
}

export type SandboxExecutionOutput = SandboxExecutionAvailableOutput
  | { kind: "not-requested" }
  | { kind: "unavailable"; reason: "missing" | "corrupt" | "io" | "released"; diagnostic: string };

export interface SandboxExecutionReceipt {
  /** Binds the identity, exact authority, outcome, cleanup and final output boundary. */
  digest: string;
  finalCursor: number;
  outputHash: string;
  stdoutBytes: number;
  stderrBytes: number;
  /** Bytes reported by the runtime but not captured in the original log. */
  omittedStdoutBytes: number;
  omittedStderrBytes: number;
}

export interface SandboxExecutionPreparation {
  policyDigest: string;
  executionDigest: string;
  summary: PreparedRunSummary;
  enforcement: EnforcementReport;
  expiresAtMs: number;
}

export type SandboxExecutionControlFailure = "unreachable" | "timeout" | "authentication-rejected" | "malformed-response" | "operation-rejected";

interface SandboxExecutionBase {
  executionId: string;
  output: SandboxExecutionOutput;
}

export type SandboxExecutionObservation =
  | (SandboxExecutionBase & {
      kind: "preparing";
      requestDigest: string;
    })
  | (SandboxExecutionBase & {
      kind: "prepared";
      requestDigest: string;
      policyDigest: string;
      executionDigest: string;
      summary: PreparedRunSummary;
      enforcement: EnforcementReport;
      expiresAtMs: number;
    })
  | (SandboxExecutionBase & {
      kind: "running";
      requestDigest: string;
      processId: string;
    })
  | (SandboxExecutionBase & {
      kind: "settled";
      requestDigest: string;
      result: Omit<SandboxRunResult, "stdout" | "stderr">;
      receipt: SandboxExecutionReceipt;
      preparation?: SandboxExecutionPreparation;
    })
  | (SandboxExecutionBase & {
      kind: "rejected";
      requestDigest: string;
      error: SandboxErrorData;
      receipt: SandboxExecutionReceipt;
      preparation?: SandboxExecutionPreparation;
    })
  | (SandboxExecutionBase & {
      kind: "unknown";
      requestDigest?: string;
      reason: "not-found" | "execution-host-unreachable" | "corrupt-record" | "storage-unavailable";
      diagnostic: string;
      controlFailure?: SandboxExecutionControlFailure;
    })
  | (SandboxExecutionBase & {
      kind: "retired";
      requestDigest: string;
      receiptDigest?: string;
      reason: "released" | "acknowledged-unknown";
      cleanupPending: boolean;
    });

export interface SandboxExecutionQuery {
  afterCursor?: number;
  /** Zero (the default) inspects status without accessing output. Maximum 1 MiB. */
  maxBytes?: number;
  waitMs?: number;
}

export interface SandboxExecutionReconciliation {
  observations: readonly SandboxExecutionObservation[];
  nextCursor?: number;
}

export interface SandboxExecutionInventoryQuery {
  afterCursor?: number;
  limit?: number;
}

/**
 * Process-local client for a private, cross-process execution repository.
 * Executions survive application-process termination. Without valid terminal
 * evidence, helper loss, operating-system restart, or storage damage can leave
 * an unknown outcome. Independently verified terminal receipts remain terminal;
 * executions are never replayed automatically.
 */
export interface SandboxExecutionRepository {
  readonly identity: string;
  readonly durability: "application-process";
  prepare(request: SandboxExecutionRequest, query?: SandboxExecutionQuery): Promise<SandboxExecutionObservation>;
  activate(executionId: string, expected: { policyDigest: string; executionDigest: string }): Promise<void>;
  inspect(executionId: string, query?: SandboxExecutionQuery): Promise<SandboxExecutionObservation>;
  writeInput(executionId: string, data: Uint8Array): Promise<void>;
  closeInput(executionId: string): Promise<void>;
  /** Cancelling a prepared execution acknowledges its durable terminal publication. */
  terminate(executionId: string): Promise<void>;
  reconcile(query?: SandboxExecutionInventoryQuery): Promise<SandboxExecutionReconciliation>;
  /** Remove an explicitly accepted unknown outcome so it no longer blocks the owning application. */
  acknowledgeUnknown(executionId: string): Promise<void>;
  /** Release evidence only after consuming it durably or explicitly accepting its loss. */
  forget(executionId: string, expected: { receiptDigest: string }): Promise<void>;
  close(): Promise<void>;
}
