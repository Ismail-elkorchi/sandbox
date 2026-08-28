import type { Buffer } from "node:buffer";
import type { SandboxEnvironment } from "./environment.js";
import type { SandboxErrorData } from "./errors.js";
import type { EnforcementReport } from "./enforcement.js";
import type { SandboxPolicy } from "./policy.js";
import type { SandboxArtifactRequest, SandboxWorkspaceChangeRequest } from "./process-options.js";
import type { EnforcementRequirements } from "./requirements.js";
import type { ResourceLimits } from "./resources.js";
import type { SandboxRunResult } from "./result.js";
import type { PreparedRunSummary } from "./summary.js";

export interface SandboxExecutionRepositoryOptions {
  /** Private host directory that owns execution identities and retained receipts. */
  directory: string;
  /** Time a terminal receipt and its output remain queryable. */
  completedRetentionMs?: number;
  /** Additional time an expired identity remains distinguishable from an unknown identity. */
  expiredIdentityRetentionMs?: number;
  /** Maximum output bytes retained for one execution. Must cover the requested sandbox output limit. */
  maxRetainedOutputBytes?: number;
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
  resources?: Partial<ResourceLimits>;
  preparedTtlMs?: number;
  process: SandboxDetachedProcessOptions;
}

export interface SandboxDetachedProcessOptions {
  executable: string;
  args?: readonly string[];
  cwd: string;
  environment?: SandboxEnvironment;
  stdin?: "pipe" | "closed";
  stdout?: "pipe" | "capture" | "discard";
  stderr?: "pipe" | "capture" | "discard";
  artifacts?: SandboxArtifactRequest;
  changeSet?: SandboxWorkspaceChangeRequest;
  resources?: Partial<ResourceLimits>;
}

export interface SandboxExecutionOutputChunk {
  cursorStart: number;
  cursorEnd: number;
  stream: "stdout" | "stderr";
  data: Buffer;
}

export interface SandboxExecutionOutput {
  cursorStart: number;
  /** Cursor immediately after the bytes returned by this observation. */
  cursorEnd: number;
  /** Cursor immediately after all output currently retained for the execution. */
  availableCursorEnd: number;
  stdoutBytes: number;
  stderrBytes: number;
  cursorExpired: boolean;
  chunks: readonly SandboxExecutionOutputChunk[];
}

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
      result: SandboxRunResult;
    })
  | (SandboxExecutionBase & {
      kind: "rejected";
      requestDigest: string;
      error: SandboxErrorData;
    })
  | (SandboxExecutionBase & {
      kind: "unknown";
      requestDigest?: string;
      reason: "not-found" | "execution-host-unreachable" | "corrupt-record";
      diagnostic: string;
    })
  | (SandboxExecutionBase & {
      kind: "expired";
      requestDigest: string;
      expiredAtMs: number;
    });

export interface SandboxExecutionQuery {
  afterCursor?: number;
  maxBytes?: number;
  waitMs?: number;
}

export interface SandboxExecutionReconciliation {
  settled: readonly SandboxExecutionObservation[];
  unresolved: readonly SandboxExecutionObservation[];
}

/**
 * Process-local client for a private, cross-process execution repository.
 * Executions survive application-process termination. Helper termination,
 * operating-system restart, power loss, and corrupt storage are reported as
 * unknown outcomes and are never replayed automatically.
 */
export interface SandboxExecutionRepository {
  readonly identity: string;
  readonly durability: "application-process";
  prepare(request: SandboxExecutionRequest, query?: SandboxExecutionQuery): Promise<SandboxExecutionObservation>;
  activate(executionId: string, expected: { policyDigest: string; executionDigest: string }): Promise<void>;
  inspect(executionId: string, query?: SandboxExecutionQuery): Promise<SandboxExecutionObservation>;
  writeInput(executionId: string, data: Uint8Array): Promise<void>;
  closeInput(executionId: string): Promise<void>;
  terminate(executionId: string): Promise<void>;
  reconcile(): Promise<SandboxExecutionReconciliation>;
  /** Remove an explicitly accepted unknown outcome so it no longer blocks the owning application. */
  acknowledgeUnknown(executionId: string): Promise<void>;
  forget(executionId: string): Promise<void>;
  close(): Promise<void>;
}
