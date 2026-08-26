import type { EnforcementReport } from "./enforcement.js";
import type { SandboxProcess } from "./process.js";
import type { PreparedRunSummary } from "./summary.js";

export interface PreparedSandboxRun {
  readonly id: string;
  readonly policyDigest: string;
  readonly executionDigest: string;
  readonly summary: PreparedRunSummary;
  readonly enforcement: EnforcementReport;
  readonly expiresAtMs: number;
  start(expected: {
    policyDigest: string;
    executionDigest: string;
    signal?: AbortSignal;
  }): Promise<SandboxProcess>;
  cancel(): Promise<void>;
}
