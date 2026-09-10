/** A path interpreted in the host filesystem. */
export interface HostPath {
  space: "host";
  path: string;
}

/** A path interpreted inside an isolated filesystem constructed for the target. */
export interface IsolatedPath {
  space: "isolated";
  path: string;
}

export type SandboxPath = HostPath | IsolatedPath;

export interface SandboxPolicy {
  filesystem: FilesystemPolicy;
  network: NetworkPolicy;
  process: ProcessPolicy;
  ipc: IpcPolicy;
}

/**
 * Host layout keeps host path names. Isolated layout constructs a new filesystem
 * and may remap resources to target paths or add synthetic directories.
 */
export type FilesystemPolicy = HostFilesystemPolicy | IsolatedFilesystemPolicy;

export interface HostFilesystemPolicy {
  kind: "host";
  resources: readonly HostFilesystemResource[];
}

export interface IsolatedFilesystemPolicy {
  kind: "isolated";
  resources: readonly IsolatedFilesystemResource[];
  masks?: readonly FilesystemMask[];
  privateHome?: SyntheticDirectoryPolicy;
  temporary?: SyntheticDirectoryPolicy;
}

export type FilesystemResourcePurpose =
  | "executable"
  | "interpreter"
  | "loader"
  | "library"
  | "cache"
  | "data";

/** Access dimensions are independent requests. Implementations reject combinations they cannot enforce. */
export interface FilesystemAccess {
  content: "read" | "read-write";
  directoryEntries: "read" | "read-write";
  metadata: "read" | "read-write";
  execution: "deny" | "allow";
}

interface FilesystemResourceBase {
  id: string;
  access: FilesystemAccess;
  purposes: readonly FilesystemResourcePurpose[];
  rootResolution?: "resolve-once" | "reject-if-link";
}

export interface HostFilesystemResource extends FilesystemResourceBase {
  path: HostPath;
}

export interface IsolatedFilesystemResource extends FilesystemResourceBase {
  source: HostPath;
  target: IsolatedPath;
}

export interface FilesystemMask {
  path: IsolatedPath;
  replacement?: "inaccessible" | "empty-file" | "empty-directory";
}

export interface SyntheticDirectoryPolicy {
  path: IsolatedPath;
  sizeBytes: number;
  executable?: boolean;
}

export type NetworkPolicy =
  | { mode: "none" }
  | ManagedNetworkPolicy
  | {
      mode: "unrestricted";
      acknowledgement: "network-is-not-restricted";
    };

export interface ManagedNetworkPolicy {
  mode: "managed";
  allow: readonly ManagedNetworkRule[];
}

export interface ManagedNetworkRule {
  transport: "tcp";
  destination:
    | {
        kind: "dns";
        name: string;
        includeSubdomains?: boolean;
        allowPrivateAddresses?: boolean;
      }
    | { kind: "ip"; cidr: string };
  ports: readonly (number | { from: number; to: number })[];
}

export interface ProcessPolicy {
  visibility: "session" | "host";
  control: "session" | "host";
  termination: {
    scope: "descendant-tree" | "process-group";
    graceMs: number;
  };
}

export interface IpcPolicy {
  visibility: "session" | "host";
}
