export interface SandboxPolicy {
  filesystem: FilesystemPolicy;
  network: NetworkPolicy;
  process: ProcessPolicy;
}

export interface FilesystemPolicy {
  runtime: RuntimeView;
  grants: readonly FilesystemGrant[];
  masks?: readonly FilesystemMask[];
  privateHome?: PrivateDirectoryPolicy;
  temporary?: TemporaryDirectoryPolicy;
}

export type RuntimeView = { kind: "system" } | { kind: "empty" };

export interface FilesystemGrant {
  hostPath: string;
  targetPath: string;
  access: "read" | "read-write";
  execution?: "deny" | "allow";
  rootResolution?: "resolve-once" | "reject-if-link";
}

export interface FilesystemMask {
  targetPath: string;
  replacement?: "inaccessible" | "empty-file" | "empty-directory";
}

export interface PrivateDirectoryPolicy {
  enabled?: boolean;
  sizeBytes?: number;
  executable?: boolean;
}

export interface TemporaryDirectoryPolicy {
  sizeBytes?: number;
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
  hostProcesses: "deny";
  hostIpc: "deny";
}
