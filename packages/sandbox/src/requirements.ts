export type IsolationBoundary = "os-process" | "hardware-virtualized";

export type GuaranteeId =
  | "runtime.setup-before-exec"
  | "runtime.no-ambient-environment"
  | "runtime.no-ambient-handles"
  | "runtime.executable-identity-bound"
  | "filesystem.grant-roots-identity-bound"
  | "filesystem.read-confined"
  | "filesystem.content-write-confined"
  | "filesystem.namespace-mutation-confined"
  | "filesystem.metadata-mutation-confined"
  | "filesystem.execution-confined"
  | "filesystem.host-user-data-hidden"
  | "network.no-external-connect"
  | "network.no-external-listen"
  | "network.no-host-loopback"
  | "network.egress-brokered"
  | "network.private-addresses-denied"
  | "process.host-enumeration-denied"
  | "process.host-control-denied"
  | "process.complete-tree-termination"
  | "ipc.host-endpoints-hidden-outside-grants"
  | "ipc.host-shared-memory-hidden"
  | "resource.wall-time-hard"
  | "resource.output-hard"
  | "resource.memory-hard"
  | "resource.cpu-time-hard"
  | "resource.process-count-hard"
  | "resource.open-files-hard"
  | "resource.single-file-size-hard"
  | "vm.boot-artifacts-verified"
  | "vm.guest-control-authenticated"
  | "vm.control-plane-hidden-from-target"
  | "vm.host-filesystem-absent-outside-imports";

export interface EnforcementRequirements {
  boundary: IsolationBoundary;
  required: readonly GuaranteeId[];
  allowExperimentalBackend?: boolean;
}

export const LINUX_PROCESS_BASELINE_REQUIREMENTS: EnforcementRequirements = {
  boundary: "os-process",
  required: [
    "runtime.setup-before-exec",
    "runtime.no-ambient-environment",
    "runtime.no-ambient-handles",
    "runtime.executable-identity-bound",
    "filesystem.grant-roots-identity-bound",
    "filesystem.read-confined",
    "filesystem.content-write-confined",
    "filesystem.namespace-mutation-confined",
    "filesystem.metadata-mutation-confined",
    "filesystem.host-user-data-hidden",
    "process.host-enumeration-denied",
    "process.host-control-denied",
    "process.complete-tree-termination",
    "resource.wall-time-hard",
    "resource.output-hard",
  ],
};
