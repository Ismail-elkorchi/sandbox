import type { ImplementationIdentity } from "./enforcement.js";
import type { SandboxIsolation } from "./sandbox.js";
import type {
  FilesystemAccess,
  FilesystemMask,
  FilesystemResourcePurpose,
  IpcPolicy,
  ManagedNetworkRule,
  ProcessPolicy,
  SandboxPath,
} from "./policy.js";
import type { ResolvedResourceLimits } from "./resources.js";

export interface PreparedResourceSummary {
  id: string;
  source: { requested: string; resolved: string; identityDigest: string };
  target: SandboxPath;
  access: FilesystemAccess;
  purposes: readonly FilesystemResourcePurpose[];
}

export type PreparedNetworkSummary =
  | { mode: "none"; topology: "private-namespace" | "no-virtual-nic" | "blocked-system-calls" }
  | { mode: "managed"; topology: "private-namespace-broker"; allow: readonly ManagedNetworkRule[] }
  | { mode: "unrestricted"; topology: "host-network-namespace" };

export interface PreparedRunSummary {
  isolation: SandboxIsolation;
  implementation: ImplementationIdentity;
  filesystem: {
    kind: "host" | "isolated";
    resourceManifestDigest: string;
    resources: readonly PreparedResourceSummary[];
    masks: readonly FilesystemMask[];
    privateHomePath: SandboxPath | null;
    temporaryPath: SandboxPath | null;
  };
  network: PreparedNetworkSummary;
  process: ProcessPolicy;
  ipc: IpcPolicy;
  resources: ResolvedResourceLimits;
  execution: {
    executable: SandboxPath;
    executableIdentityDigest: string;
    executableContentSha256: string;
    args: readonly string[];
    cwd: SandboxPath;
    cwdIdentityDigest: string;
    environmentNames: readonly string[];
    sensitiveEnvironmentNames: readonly string[];
    stdin: "pipe" | "closed";
    stdout: "pipe" | "capture" | "discard";
    stderr: "pipe" | "capture" | "discard";
  };
}

export type PreparedSessionSummary = Omit<PreparedRunSummary, "execution">;

export interface PreparedProcessSummary {
  execution: PreparedRunSummary["execution"];
}
