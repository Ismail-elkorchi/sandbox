import type { EnforcementReport } from "./enforcement.js";
import type { SandboxProcess } from "./process.js";
import type { SandboxSession } from "./session.js";
import type { PreparedProcessSummary, PreparedSessionSummary } from "./summary.js";

export interface PreparedSandboxSession {
  readonly id: string;
  readonly policyDigest: string;
  readonly summary: PreparedSessionSummary;
  readonly enforcement: EnforcementReport;
  readonly expiresAtMs: number;
  activate(expected: {
    policyDigest: string;
    signal?: AbortSignal;
  }): Promise<SandboxSession>;
  cancel(): Promise<void>;
}

export interface PreparedSandboxProcess {
  readonly id: string;
  readonly policyDigest: string;
  readonly executionDigest: string;
  readonly summary: PreparedProcessSummary;
  readonly expiresAtMs: number;
  start(expected: {
    policyDigest: string;
    executionDigest: string;
    signal?: AbortSignal;
  }): Promise<SandboxProcess>;
  cancel(): Promise<void>;
}
