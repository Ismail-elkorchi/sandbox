import type { SandboxIsolation } from "./sandbox.js";
import type { FilesystemMask, ManagedNetworkRule, ProcessPolicy } from "./policy.js";
import type { ResourceLimits } from "./resources.js";

export interface PreparedGrantSummary {
  requestedHostPath: string;
  resolvedHostPath: string;
  hostIdentityDigest: string;
  targetPath: string;
  access: "read" | "read-write";
  execution: "deny" | "allow";
}

export type PreparedNetworkSummary =
  | { mode: "none"; topology: "private-namespace" | "no-virtual-nic" }
  | { mode: "managed"; topology: "private-namespace-broker"; allow: readonly ManagedNetworkRule[] }
  | { mode: "unrestricted"; topology: "host-network-namespace" };

export interface PreparedRunSummary {
  isolation: SandboxIsolation;
  backend: {
    id: string;
    version: string;
    stability: "stable" | "experimental";
  };
  filesystem: {
    runtimeView: "system" | "empty";
    runtimeManifestDigest: string;
    grants: readonly PreparedGrantSummary[];
    masks: readonly FilesystemMask[];
    privateHomePath: string | null;
    temporaryPath: string;
  };
  network: PreparedNetworkSummary;
  process: ProcessPolicy;
  resources: ResourceLimits;
  execution: {
    executable: string;
    executableIdentityDigest?: string;
    executableContentSha256?: string;
    args: readonly string[];
    cwd: string;
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
  resources: ResourceLimits;
  execution: PreparedRunSummary["execution"];
}
