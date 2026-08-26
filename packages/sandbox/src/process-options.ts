import type { SandboxEnvironment } from "./environment.js";
import type { ResourceLimits } from "./resources.js";

export interface SandboxProcessOptions {
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
  signal?: AbortSignal;
}

export interface SandboxWorkspaceChangeRequest {
  maxBytes: number;
}

export interface SandboxArtifactRequest {
  paths: readonly string[];
  maxBytes: number;
}
