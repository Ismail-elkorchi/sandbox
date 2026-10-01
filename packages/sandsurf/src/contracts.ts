import type { Artifact } from "./artifacts.js";
import type { ExecutionInspection, ExecutionLineage, Receipt } from "./execution.js";
import type { Execution } from "./executions.js";
import type { Image } from "./images.js";
import type { OutputBoundary } from "./sandsurf-protocol.js";

export type DesiredMachineState = "running" | "paused" | "stopped" | "suspended" | "destroyed";

export interface AuthorityChange { readonly kind: "machine-create" | "lifecycle" | "image-import" | "image-publish" | "image-release" | "evidence-loss" | "host-import" | "host-export" | "host-apply" | "snapshot" | "fork" | "resource-increase" | "network-access" | "port-exposure" | "secret-delivery" | "secret-revocation"; readonly machineId: string; readonly operationId: string; readonly request: Readonly<Record<string, unknown>>; }

export type AuthorityDecision = boolean | { readonly approvalId: string };

export type SandsurfAuthorizer = (change: AuthorityChange) => AuthorityDecision | Promise<AuthorityDecision>;

export interface SandsurfOpenOptions { readonly directory: string; readonly authorizer?: SandsurfAuthorizer; readonly service?: "auto" | "connect"; }

export interface ResourceEnvelope {
  /** Virtual CPU topology; CPU time is limited separately per 100ms period. */
  readonly vcpus: number; readonly memoryMiB: number; readonly diskBytes: number;
  readonly outputBytes?: number; readonly managedExecutions?: number;
  readonly cpuQuotaMicros?: number; readonly hostOverheadBytes?: number;
  readonly physicalStorageBytes?: number; readonly snapshotBytes?: number;
  readonly channels?: number; readonly inflightRequests?: number;
  readonly networkConnections?: number; readonly networkBytesPerSecond?: number; readonly networkQueueBytes?: number;
}

export type ResourceChangeMode = "live" | "requires-reboot" | "unsupported";

export interface ResourceChangeAssessment { readonly mode: ResourceChangeMode; readonly reasons: readonly string[]; }

export interface ResourceUpdateResult { readonly machine: MachineInspection; readonly assessment: ResourceChangeAssessment; }

export type MeasurementSource = "unavailable" | "host-cgroup" | "host-filesystem" | "host-retention" | "host-admission" | "host-network" | "guest-reported";

export interface ResourceProvenance { readonly cpu: MeasurementSource; readonly memory: MeasurementSource; readonly io: MeasurementSource; readonly storage: MeasurementSource; readonly output: MeasurementSource; readonly executions: MeasurementSource; readonly channels: MeasurementSource; readonly network: MeasurementSource; }

export interface MachineCreateOptions {
  /** Identity whose bounded storage slot was provisioned by the operator. */
  readonly id: string;
  readonly operationId?: string;
  readonly image: string;
  readonly resources: ResourceEnvelope;
  readonly user?: string;
  readonly environment?: Readonly<Record<string, string>>;
  readonly workingDirectory?: string;
  readonly lifetime?: MachineLifetimePolicy;
}

export interface MachineRevisionPrecondition { readonly expectedRevision?: number; }

export interface MachineGenerationPrecondition { readonly expectedGeneration?: number; }

export interface MachineLifecycleOptions extends MachineRevisionPrecondition { readonly operationId?: string; }

export interface MachineLifetimePolicy { readonly expiresAtUnixMs?: number; readonly expirationAction?: "stop" | "destroy"; }

export type SnapshotKind = "disk" | "full";

export type SnapshotConsistency = "crash" | "machine";

export interface SnapshotInspection { readonly id: string; readonly operationId: string; readonly machineId: string; readonly expectedGeneration: number; readonly expectedRevision: number; readonly kind: SnapshotKind; readonly parent: string | null; readonly requestDigest: string; readonly phase: "admitted" | "capturing" | "ready"; readonly imageDigest: string; readonly resources: Required<ResourceEnvelope>; readonly consistency: SnapshotConsistency | null; readonly systemDiskDigest: string | null; readonly systemDiskBytes: number; readonly manifestDigest: string | null; readonly sensitive: boolean; }

export interface SnapshotCreateOptions extends MachineGenerationPrecondition, MachineRevisionPrecondition { readonly id?: string; readonly operationId?: string; readonly kind?: SnapshotKind; readonly parent?: string; }

export interface DerivedImagePublishOptions { readonly operationId?: string; readonly allowSensitive?: boolean; }

export interface MachineForkOptions { readonly id: string; readonly operationId?: string; readonly resources?: ResourceEnvelope; readonly lifetime?: MachineLifetimePolicy; }

export type Qualification = { readonly kind: "qualified"; readonly evidence: string } | { readonly kind: "unqualified"; readonly reasons: readonly string[] };

export type Capability = { readonly kind: "supported"; readonly qualification: Qualification } | { readonly kind: "unsupported"; readonly reasons: readonly string[] };

export interface GuestPowerCapabilities { readonly shutdown: Capability; readonly reboot: Capability; }

export interface ResourceCapabilities { readonly nativeTopology: Capability; readonly cpuTime: Capability; readonly aggregateHostMemory: Capability; readonly managedAdmission: Capability; readonly outputRetention: Capability; readonly storageReservations: Capability; readonly networkEnvelope: Capability; readonly aggregatePhysicalStorage: Capability; readonly sharedHostWorkers: Capability; readonly completeEnforcement: Capability; }

export interface NativeQualificationConfiguration { readonly buildDigest: string; readonly platform: string; readonly architecture: string; readonly hardwareDigest: string; readonly engine: "firecracker" | "apple-virtualization" | "hyper-v"; readonly engineDigest: string; readonly imageDigest: string; readonly kernelDigest: string; readonly initramfsDigest: string | null; readonly nicConfigurationDigest: string; readonly storageConfigurationDigest: string; readonly resources: Required<ResourceEnvelope>; }

export interface RetainedQualification { readonly run: { readonly configuration: NativeQualificationConfiguration; readonly scope: "lifecycle" | "resources" | "cpu-time" | "host-memory" | "storage-budgets" | "managed-channels" | "native-network" | "disk-snapshots" | "full-state" | "images" | "distribution"; readonly observedUnixMillis: number; readonly passedChecks: readonly string[]; readonly evidenceDigest: string; }; readonly acceptedBy: string; readonly acceptedUnixMillis: number; readonly recordDigest: string; }

export interface HostInspection { readonly hostId: string; readonly platform: string; readonly architecture: string; readonly guestArchitecture: string; readonly guestPlatform: string; readonly engine: "firecracker" | "apple-virtualization" | "hyper-v"; readonly lifecycle: Qualification; readonly fullState: Qualification; readonly images: Qualification; readonly imageWorkers: Capability; readonly resources: ResourceCapabilities; readonly qualificationRecords: readonly RetainedQualification[]; readonly qualificationIssues: readonly string[]; readonly guestPower: GuestPowerCapabilities; readonly console: Capability; readonly defaultImageDigest: string | null; }

export interface ImageDefaults { readonly environment: Readonly<Record<string, string>>; readonly user: string | null; readonly workingDirectory: string | null; }

export interface ManagementReport { readonly generation: number; readonly identity: { readonly bootId: string; readonly instanceId: string }; readonly observedUnixMillis: number; }

export type ManagementObservation = { readonly kind: "current"; readonly value: ManagementReport } | { readonly kind: "unavailable"; readonly lastKnown: ManagementReport | null };

export type MachineState = "creating" | "starting" | "running" | "paused" | "stopped" | "suspended" | "restoring" | "destroying" | "destroyed" | "failed";

export type ObservationCause = { readonly kind: "lifecycle" | "configuration"; readonly operationId: string } | { readonly kind: "native" | "guest-reset" };

export interface NativeMachineObservation { readonly machineId: string; readonly generation: number; readonly sequence: number; readonly state: MachineState; readonly appliedRevision: number; readonly cause: ObservationCause; readonly evidenceDigest: string; }

export type MachineObservation = { readonly kind: "current"; readonly value: NativeMachineObservation } | { readonly kind: "unavailable"; readonly lastKnown: NativeMachineObservation | null };

export interface ObservationReference { readonly machineId: string; readonly generation: number; readonly sequence: number; readonly digest: string; }

export interface MachineLifecycleIntent { readonly machineId: string; readonly operationId: string; readonly desired: DesiredMachineState; readonly revision: number; readonly requestDigest: string; readonly completion: ObservationReference | null; }

export type StoragePayload = { readonly kind: "present" | "capacity-mismatch"; readonly fileBytes: number } | { readonly kind: "missing" | "unavailable" };

/** Host storage observations do not attest to the integrity of the Linux filesystem. */
export type StorageInspection = { readonly kind: "current"; readonly phase: "preparing" | "published" | "attached" | "replacing" | "retiring" | "retired"; readonly format: "raw" | "vhdx"; readonly capacityBytes: number; readonly operationId: string | null; readonly payload: StoragePayload } | { readonly kind: "unavailable"; readonly reason: "ownership-missing" | "ownership-invalid" | "access-unavailable" };

export interface MachineInspection { readonly id: string; readonly imageDigest: string; readonly runtimeConfiguration: RuntimeConfiguration; readonly configurationRevision: number; readonly reservation: "held" | "released"; readonly knownSensitive: boolean; readonly lifecycleIntent: MachineLifecycleIntent; readonly machine: MachineObservation; readonly management: ManagementObservation; readonly storage: StorageInspection; readonly executionDefaults: ImageDefaults; readonly lifetime: Readonly<{ expiresAtUnixMillis: number | null; expirationAction: "stop" | "destroy" }>; readonly lastActivityUnixMillis: number; }

export type NetworkDestination = { readonly kind: "ip"; readonly cidr: string; readonly allowPrivateAddresses?: boolean };

export interface NetworkRule { readonly plane: "tcp" | "udp"; readonly destination: NetworkDestination; readonly ports: readonly ({ readonly from: number; readonly to: number } | number)[]; }

export interface NetworkPolicy { readonly rules: readonly NetworkRule[]; }

export interface ExposureSpec { readonly guestAddress?: string; readonly guestPort: number; readonly hostAddress?: string; readonly hostPort?: number; readonly public?: boolean; }

export interface Exposure { readonly id: string; readonly machineId: string; readonly revision: number; readonly spec: { readonly guestAddress: string; readonly guestPort: number; readonly hostAddress: string; readonly hostPort: number; readonly public: boolean }; readonly active: boolean; readonly boundPort: number | null; }

export interface RuntimeConfiguration { readonly network: NetworkPolicy; readonly exposures: readonly Exposure[]; readonly resources: Required<ResourceEnvelope>; }

export interface ResourceUsage { readonly provenance: ResourceProvenance; readonly hostCounterEpoch: string | null; readonly channelsCurrent: number | null; readonly inflightRequestsCurrent: number | null; readonly cpuMicros: number | null; readonly memoryCurrent: number | null; readonly memoryPeak: number | null; readonly diskLogicalBytes: number; readonly diskAllocatedBytes: number; readonly ioReadBytes: number | null; readonly ioWriteBytes: number | null; readonly outputRetainedBytes: number; readonly networkRxBytes: number; readonly networkTxBytes: number; readonly networkConnections: number; readonly executionsCurrent: number; readonly complete: boolean; readonly source: string; readonly observedUnixMillis: number; }

export interface SecretVersion { readonly id: string; readonly version: string; readonly bytes: number; }

export interface SecretDeliveryResult { readonly operationId: string; readonly machineId: string; readonly secret: SecretVersion; readonly disclosure: "not-sent" | "possible" | "guest-reported-received"; readonly revoked: boolean; }

export interface SecretRevocation {
  readonly operationId: string;
  readonly machineId: string;
  readonly secret: SecretVersion;
  readonly terminateRecipients: boolean;
  readonly futureDeliveryRevoked: true;
  readonly guestCleanupReport: null | {
    readonly filesRemoved: number;
    readonly environmentBindingsRemoved: number;
    readonly recipientsTerminated: readonly string[];
    readonly recipientsAlreadyStopped: readonly string[];
    readonly residualCopiesPossible: boolean;
    readonly actionsReportedComplete: boolean;
  };
}

export type OciImageSource = { readonly kind: "layout"; readonly path: string } | { readonly kind: "archive"; readonly path: string } | { readonly kind: "registry"; readonly reference: string; readonly credential?: SecretVersion };

/** Validate a complete OCI OS filesystem against explicit native boot artifacts.
 * OCI entrypoint/command does not control machine lifetime. Guest integration
 * must be installed in the source OS; it is never inferred from the boot image.
 */
export interface MachineImageRecipe { readonly bootImage: string | Image; }

export interface ImageImportOptions { readonly source?: OciImageSource; readonly reference?: string; readonly recipe: MachineImageRecipe; readonly platform?: string; readonly operationId?: string; }

/** Import an immutable complete-machine bundle by the SHA-256 of its exact
 * manifest bytes. The host retains its own verified copy, not the source path.
 * Sensitivity preserves declared image provenance; absence of a known
 * disclosure is not proof that the complete disk contains no secrets.
 */
export interface NativeImageImportOptions { readonly manifestPath: string; readonly manifestDigest: string; readonly operationId?: string; }

export interface ImageInspection { readonly digest: string; readonly sourceDigest: string; readonly platform: string; readonly architecture: string; readonly logicalBytes: number; readonly storageBytes: number; readonly provenanceDigest: string; readonly sensitive: boolean; }

export interface ImageReleaseInspection { readonly operationId: string; readonly imageDigest: string; readonly requestDigest: string; readonly cleanupPending: boolean; }

export interface ReceiptView { readonly receipt: Receipt; readonly digest: string; }

export type OperationDelivery = "admitted" | "dispatched" | "applied" | "not-applied" | "unknown";

export type OperationObservation =
  | { readonly kind: "lifecycle"; readonly intent: MachineLifecycleIntent }
  | { readonly kind: "configuration"; readonly revision: number; readonly configuration: RuntimeConfiguration }
  | { readonly kind: "transfer"; readonly applied: boolean }
  | { readonly kind: "image-import"; readonly phase: "admitted" | "published"; readonly image: ImageInspection | null }
  | { readonly kind: "image-release"; readonly imageDigest: string; readonly cleanupPending: boolean }
  | { readonly kind: "secret-delivery"; readonly secret: SecretVersion; readonly disclosure: "not-sent" | "possible" | "guest-reported-received"; readonly revoked: boolean; readonly revocationOperation: string | null }
  | { readonly kind: "secret-put"; readonly secret: SecretVersion; readonly applied: boolean }
  | { readonly kind: "secret-revocation"; readonly revocation: SecretRevocation }
  | { readonly kind: "snapshot"; readonly snapshot: SnapshotInspection }
  | { readonly kind: "rollback"; readonly snapshotId: string; readonly expectedRevision: number; readonly phase: "admitted" | "applied"; readonly evidenceDigest: string | null }
  | { readonly kind: "guest"; readonly generation: number; readonly requestKind: "spawn" | "close-input" | "write-input" | "acquire-terminal-input" | "release-terminal-input" | "resize-terminal" | "signal" | "terminate" | "filesystem"; readonly delivery: OperationDelivery; readonly evidenceDigest: string | null }
  | { readonly kind: "receipt-acknowledgement"; readonly executionId: string; readonly receiptDigest: string }
  | { readonly kind: "output-seal"; readonly segment: OutputSegmentInspection }
  | { readonly kind: "evidence-release"; readonly executionId: string; readonly status: ReleaseStatus };

/** An observation of its authoritative store, never client-side authority. */
export interface OperationInspection {
  readonly operationId: string;
  readonly machineId: string | null;
  readonly owner: "host-authority" | "guardian-journal";
  readonly requestDigest: string | null;
  readonly observation: OperationObservation;
}

export interface CaptureCommitment { readonly storeId: string; readonly commitmentId: string; readonly manifestDigest: string; readonly receiptDigest: string; readonly output: OutputBoundary; }

export type ReleaseDisposition = { readonly kind: "complete-capture"; readonly commitment: CaptureCommitment } | { readonly kind: "continuing-retention"; readonly segment: string } | { readonly kind: "authorized-loss"; readonly authorization?: string };

export interface OutputSegmentInspection { readonly id: string; readonly machineId: string; readonly executionId: string; readonly generation: number; readonly output: OutputBoundary; }

export interface ReleaseStatus { readonly requestDigest: string; readonly cleanupPending: boolean; }

export interface ConfigurationDeliveryObservation {
  readonly operationId: string;
  readonly revision: number;
  readonly requestDigest: string;
  readonly configuration: RuntimeConfiguration;
  readonly delivery: OperationDelivery;
  readonly evidenceDigest: string | null;
  readonly observation: ObservationReference | null;
}

/** Typed projections of retained facts. Guest execution and delivery reports
 * remain observations; a receipt event is neither acceptance nor byte retention.
 */
export type MachineEventValue =
  | { readonly kind: "machine"; readonly observation: NativeMachineObservation }
  | { readonly kind: "guest-operation"; readonly operation: OperationInspection }
  | { readonly kind: "lifecycle-operation"; readonly operation: ConfigurationDeliveryObservation & { readonly desired: DesiredMachineState } }
  | { readonly kind: "configuration-operation"; readonly operation: ConfigurationDeliveryObservation }
  | { readonly kind: "execution"; readonly execution: ExecutionInspection }
  | { readonly kind: "output"; readonly executionId: string; readonly boundary: OutputBoundary }
  | { readonly kind: "receipt"; readonly executionId: string; readonly receiptDigest: string }
  | { readonly kind: "evidence-release"; readonly executionId: string; readonly requestDigest: string; readonly cleanupPending: boolean };

export interface MachineEvent { readonly cursor: number; readonly value: MachineEventValue; readonly digest: string; }

export interface MachineEventPage { readonly cursor: number; readonly available: number; readonly events: readonly MachineEvent[]; }

/** Host-retained serial bytes. Loss ranges count observed bytes that exceeded
 * the fixed capture budget; captureFailed means completeness is unavailable. */
export interface ConsolePage {
  readonly generation: number;
  readonly after: number;
  readonly cursor: number;
  readonly available: number;
  readonly bytes: Uint8Array;
  readonly loss: { readonly from: number; readonly to: number } | null;
  readonly open: boolean;
  readonly captureFailed: boolean;
}

export interface TerminalSize { readonly columns: number; readonly rows: number; readonly pixelWidth?: number; readonly pixelHeight?: number; }

export interface ExecutionOperationOptions extends MachineGenerationPrecondition { readonly operationId?: string; }

export interface ExecutionSignalOptions extends ExecutionOperationOptions { readonly group?: boolean; }

export interface ExecutionTerminateOptions extends ExecutionOperationOptions { readonly graceMillis?: number; }

export interface SpawnOptions extends MachineGenerationPrecondition { readonly operationId?: string; readonly executionId?: string; readonly argv: readonly string[]; readonly cwd?: string; readonly environment?: Readonly<Record<string, string>>; readonly user?: string; readonly stdio?: "pipes" | "terminal"; readonly terminalSize?: TerminalSize; readonly activeDeadlineMs?: number; readonly elapsedDeadlineUnixMs?: number; readonly outputBytes?: number; }

export type ExecOptions = SpawnOptions & { readonly signal?: AbortSignal };

export type ShellOptions = Omit<SpawnOptions, "argv"> & { readonly shell?: string };

export type ExecShellOptions = Omit<ExecOptions, "argv"> & { readonly shell?: string };

export interface ExecResult { readonly process: Execution; readonly inspection: ExecutionInspection; }

export type ExecutionObservation = { readonly kind: "current"; readonly value: ExecutionInspection } | { readonly kind: "unavailable"; readonly lastKnown: ExecutionInspection | null };

export interface ExecutionStatus { readonly executionId: string; readonly generation: number; readonly lineage: ExecutionLineage | null; readonly report: ExecutionObservation; readonly interruption: NativeMachineObservation | null; }

export type TerminalOpenOptions = Omit<SpawnOptions, "stdio" | "terminalSize"> & { readonly terminalSize?: TerminalSize; readonly inputLeaseId?: string; readonly inputLeaseOperationId?: string };

export interface OutputChunk { readonly cursor: number; readonly stream: "stdout" | "stderr" | "terminal"; readonly bytes: Uint8Array; readonly digest: string; }

export interface OutputPage { readonly after: number; readonly available: number; readonly chunks: readonly OutputChunk[]; readonly requiredBytes?: number; }

export type FileExpectation = { readonly kind: "any" } | { readonly kind: "absent" };

export interface FileOperationOptions extends MachineGenerationPrecondition { readonly operationId?: string; }

export interface ArtifactInspection {
  readonly id: string; readonly machineId: string; readonly requestDigest: string;
  readonly manifestDigest: string; readonly entries: number; readonly bytes: number;
  /** Captured bytes are immutable; the source tree was read live, not atomically. */
  readonly consistency: "live";
}

export interface ArtifactCaptureOptions extends MachineGenerationPrecondition, MachineRevisionPrecondition {
  readonly operationId?: string; readonly maximumBytes?: number;
}

export interface ArtifactImportOptions extends ArtifactCaptureOptions {
  readonly source: string; readonly destination: string | Uint8Array; readonly exclusions?: readonly string[];
}

export interface ArtifactApplyOptions {
  readonly destination: string; readonly operationId?: string; readonly base?: Artifact;
}

export interface TreeEntry { readonly path: string; readonly kind: "directory" | "file" | "symlink"; readonly mode: number; readonly size: number; readonly digest: string | null; readonly target: readonly number[] | null; }

export interface TreeManifest { readonly digest: string; readonly entries: readonly TreeEntry[]; readonly captureOperationId?: string; }

export type TreeChange = { readonly kind: "upsert"; readonly entry: TreeEntry } | { readonly kind: "delete"; readonly path: string };

export interface ChangeSet { readonly baseManifestDigest: string; readonly base: readonly TreeEntry[]; readonly changes: readonly TreeChange[]; readonly digest: string; readonly captureOperationId: string; }

export interface HostApplyReport { readonly operationId: string; readonly changeSetDigest: string; readonly applied: number; readonly recovered: boolean; }
