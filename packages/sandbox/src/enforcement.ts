import type { GuaranteeId, IsolationBoundary } from "./requirements.js";

export type GuaranteeStatus = "satisfied" | "unsatisfied";
export type EnforcementLayer =
  | "kernel"
  | "supervisor"
  | "broker"
  | "hypervisor"
  | "guest-kernel"
  | "guest-agent"
  | "composition";

export interface GuaranteeFact {
  id: GuaranteeId;
  status: GuaranteeStatus;
  enforcedBy?: readonly EnforcementLayer[];
  mechanism?: readonly string[];
  evidence?: readonly string[];
  caveats?: readonly string[];
}

export interface EnforcementCaveat {
  code: string;
  message: string;
  affectedGuarantees: readonly GuaranteeId[];
}

export interface ImplementationIdentity {
  id: string;
  version: string;
  buildId: string;
  conformanceManifestId: string;
  stability: "stable" | "experimental";
}

export interface EnforcementReport {
  boundary: { kind: IsolationBoundary };
  implementation: ImplementationIdentity & { mechanism: readonly string[] };
  host: {
    platform: NodeJS.Platform;
    architecture: string;
    pathStyle: "posix" | "windows";
  };
  target: {
    operatingSystem: "linux" | "macos" | "windows";
    pathStyle: "posix" | "windows";
  };
  guarantees: readonly GuaranteeFact[];
  filesystem: {
    kind: "host" | "isolated";
    resourceManifestDigest: string;
    visibleRoots: readonly string[];
  };
  caveats: readonly EnforcementCaveat[];
}
