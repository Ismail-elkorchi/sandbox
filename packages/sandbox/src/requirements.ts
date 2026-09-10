export type IsolationBoundary = "os-process" | "hardware-virtualized";

export type GuaranteeId =
  | "runtime.setup-before-exec"
  | "runtime.no-ambient-environment"
  | "runtime.no-ambient-handles"
  | "runtime.executable-identity-bound"
  | "filesystem.resource-identities-bound"
  | "filesystem.content-read-confined"
  | "filesystem.content-write-confined"
  | "filesystem.directory-entry-mutation-confined"
  | "filesystem.metadata-mutation-confined"
  | "filesystem.execution-confined"
  | "filesystem.name-visibility-confined"
  | "filesystem.isolated-layout"
  | "network.no-external-connect"
  | "network.no-external-listen"
  | "network.no-host-loopback"
  | "network.egress-brokered"
  | "network.private-addresses-denied"
  | "process.host-visibility-denied"
  | "process.host-control-denied"
  | "process.descendant-tree-termination"
  | "process.group-termination"
  | "ipc.host-endpoints-hidden"
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

/** Policy-derived guarantees are always required. These are additional caller constraints. */
export interface EnforcementRequirements {
  additional?: readonly GuaranteeId[];
  allowExperimentalImplementations?: boolean;
}
