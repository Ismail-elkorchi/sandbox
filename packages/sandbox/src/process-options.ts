import type { SandboxEnvironment } from "./environment.js";
import type { SandboxPath } from "./policy.js";

export interface SandboxProcessOptions {
  executable: SandboxPath;
  args?: readonly string[];
  cwd: SandboxPath;
  environment?: SandboxEnvironment;
  stdin?: "pipe" | "closed";
  stdout?: "pipe" | "capture" | "discard";
  stderr?: "pipe" | "capture" | "discard";
  artifacts?: SandboxArtifactRequest;
  changeSet?: SandboxWorkspaceChangeRequest;
  signal?: AbortSignal;
}

export interface SandboxWorkspaceChangeRequest {
  root: SandboxPath;
  maxBytes: number;
}

export interface SandboxArtifactRequest {
  paths: readonly SandboxPath[];
  maxBytes: number;
}
