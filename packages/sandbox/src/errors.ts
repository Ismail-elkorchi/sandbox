import type { EnforcementReport } from "./enforcement.js";

export interface SandboxErrorData {
  code: string;
  message: string;
  phase:
    | "probe"
    | "validate"
    | "prepare"
    | "activate"
    | "spawn"
    | "execute"
    | "terminate"
    | "artifact-export"
    | "cleanup";
  targetExecuted: boolean;
  backend?: string;
  platform?: string;
  causeCode?: string;
  enforcement?: EnforcementReport;
}

export class SandboxError extends Error {
  readonly data: SandboxErrorData;

  constructor(data: SandboxErrorData) {
    super(data.message);
    this.name = new.target.name;
    this.data = Object.freeze({ ...data });
  }
}

export class SandboxUnsupportedError extends SandboxError {}
export class SandboxRequirementError extends SandboxError {}
export class SandboxPolicyError extends SandboxError {}
export class SandboxPreparationError extends SandboxError {}
export class SandboxPreparationExpiredError extends SandboxError {}
export class SandboxDigestMismatchError extends SandboxError {}
export class SandboxRuntimeNotFoundError extends SandboxError {}
export class SandboxRuntimeIntegrityError extends SandboxError {}
export class SandboxProtocolError extends SandboxError {}
export class SandboxSetupError extends SandboxError {}
export class SandboxSpawnError extends SandboxError {}
export class SandboxTerminationError extends SandboxError {}
export class SandboxArtifactError extends SandboxError {}
export class SandboxCleanupError extends SandboxError {}
export class SandboxRuntimeCrashedError extends SandboxError {}

export function errorFromData(data: SandboxErrorData): SandboxError {
  const key = data.code.split(".", 1)[0] ?? "";
  switch (key) {
    case "unsupported": return new SandboxUnsupportedError(data);
    case "requirement": return new SandboxRequirementError(data);
    case "policy": return new SandboxPolicyError(data);
    case "preparation": return new SandboxPreparationError(data);
    case "preparation_expired": return new SandboxPreparationExpiredError(data);
    case "digest_mismatch": return new SandboxDigestMismatchError(data);
    case "runtime_not_found": return new SandboxRuntimeNotFoundError(data);
    case "runtime_integrity": return new SandboxRuntimeIntegrityError(data);
    case "protocol": return new SandboxProtocolError(data);
    case "setup": return new SandboxSetupError(data);
    case "spawn": return new SandboxSpawnError(data);
    case "termination": return new SandboxTerminationError(data);
    case "artifact": return new SandboxArtifactError(data);
    case "cleanup": return new SandboxCleanupError(data);
    case "runtime_crashed": return new SandboxRuntimeCrashedError(data);
    default: return new SandboxError(data);
  }
}
