import type { EnforcementReport } from "./enforcement.js";
import type { PreparedSandboxProcess } from "./prepared-session.js";
import type { SandboxProcessOptions } from "./process-options.js";
import type { SandboxRunResult } from "./result.js";

export interface SandboxSession {
  readonly id: string;
  readonly policyDigest: string;
  readonly enforcement: EnforcementReport;
  prepare(process: SandboxProcessOptions): Promise<PreparedSandboxProcess>;
  run(process: SandboxProcessOptions): Promise<SandboxRunResult>;
  close(): Promise<void>;
}
