import type { EnforcementReport } from "./enforcement.js";
import type { SandboxErrorData } from "./errors.js";

export interface SandboxArtifactEntry {
  path: string;
  kind: "directory" | "regular-file" | "symbolic-link";
  mode: number;
  modifiedUnixMs: number;
  contentHex?: string;
  linkTarget?: string;
  sha256?: string;
}

export interface SandboxArtifactBundle {
  digest: string;
  files: readonly SandboxArtifactEntry[];
  bytes: number;
}

export interface SandboxRunResult {
  processId: string;
  policyDigest: string;
  executionDigest: string;
  termination: SandboxTermination;
  stdout?: Buffer;
  stderr?: Buffer;
  enforcement: EnforcementReport;
  violations: readonly StructuredViolation[];
  usage: SandboxResourceUsage;
  cleanup: SandboxCleanupReport;
  artifacts?: SandboxArtifactBundle;
  changeSets?: readonly SandboxWorkspaceChangeSet[];
}

export interface SandboxWorkspaceChangeSet {
  targetPath: string;
  bytes: number;
  changeSet: SandboxChangeSet;
}

export interface SandboxChangeSet {
  formatVersion: 1;
  baseManifestDigest: string;
  base: readonly SandboxChangeBaseEntry[];
  operations: readonly SandboxChangeOperation[];
  digest: string;
}

export interface SandboxChangeBaseEntry {
  path: string;
  kind: SandboxArtifactEntry["kind"];
  sha256?: string;
  mode: number;
  modifiedUnixMs: number;
  linkTarget?: string;
}

export type SandboxChangeOperation =
  | { kind: "upsert"; entry: SandboxArtifactEntry }
  | { kind: "delete"; path: string }
  | { kind: "rename"; from: string; to: string };

export type SandboxTermination =
  | { reason: "exit"; code: number }
  | { reason: "signal"; signal: string }
  | { reason: "timeout" }
  | { reason: "cancelled" }
  | { reason: "memory-limit" }
  | { reason: "cpu-limit" }
  | { reason: "process-limit" }
  | { reason: "output-limit" }
  | { reason: "single-file-size-limit" }
  | { reason: "policy-kill"; violation: StructuredViolation }
  | { reason: "runtime-failure"; error: SandboxErrorData };

export type SandboxEvent =
  | { kind: "violation"; violation: StructuredViolation }
  | {
      kind: "resource-warning";
      resource: string;
      observed: number;
      limit: number;
    }
  | { kind: "termination-started"; reason: string }
  | { kind: "cleanup-warning"; code: string; message: string };

export interface StructuredViolation {
  id: string;
  kind: string;
  processId: string;
  timestampMs: number;
  mechanism: string;
  details: Readonly<Record<string, string | number | boolean>>;
}

export interface SandboxResourceUsage {
  wallTimeMs: number;
  cpuTimeMs?: number;
  peakMemoryBytes?: number;
  processesCreated?: number;
  stdoutBytes: number;
  stderrBytes: number;
  maxConcurrentProcesses?: number;
  networkConnections?: number;
}

export interface SandboxCleanupReport {
  completed: boolean;
  failures: readonly {
    code: string;
    resource: string;
    message: string;
  }[];
}
