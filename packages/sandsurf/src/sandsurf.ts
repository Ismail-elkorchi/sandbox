import { createHash, randomUUID } from "node:crypto";
import { isAbsolute, resolve } from "node:path";
import { isIP } from "node:net";
import { NativeHostClient, SandsurfHostError, integer, record, text } from "./native-host.js";
import { createSandsurfGuestPath, sandsurfDigest } from "./sandsurf-protocol.js";

const transport = Symbol("host transport");
const authorize = Symbol("host approval");
const dispatchGuest = Symbol("guest command");
const queryGuest = Symbol("guest query");
const observed = Symbol("cached observation");
const observe = Symbol("observe host response");
const executionFence = Symbol("execution generation fence");

export type DesiredMachineState = "running" | "paused" | "stopped" | "suspended" | "destroyed";
export interface AuthorityChange { readonly kind: "machine-create" | "lifecycle" | "image-import" | "image-publish" | "image-release" | "evidence-loss" | "host-import" | "host-export" | "host-apply" | "snapshot" | "fork" | "resource-increase" | "network-access" | "port-exposure" | "secret-delivery" | "secret-revocation"; readonly machineId: string; readonly operationId: string; readonly request: Readonly<Record<string, unknown>>; }
export type AuthorityDecision = boolean | { readonly approvalId: string };
export type SandsurfAuthorizer = (change: AuthorityChange) => AuthorityDecision | Promise<AuthorityDecision>;
export interface SandsurfOpenOptions { readonly directory: string; readonly authorizer?: SandsurfAuthorizer; readonly service?: "auto" | "connect"; }
export interface ResourceEnvelope { readonly vcpus: number; readonly memoryMiB: number; readonly diskBytes: number; readonly outputBytes?: number; readonly managedExecutions?: number; }
export interface MachineCreateOptions {
  readonly id?: string;
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
export interface MachineForkOptions { readonly id?: string; readonly operationId?: string; readonly resources?: ResourceEnvelope; readonly lifetime?: MachineLifetimePolicy; }
export type Qualification = { readonly kind: "qualified"; readonly evidence: string } | { readonly kind: "unqualified"; readonly reasons: readonly string[] };
export interface HostInspection { readonly hostId: string; readonly platform: string; readonly architecture: string; readonly guestArchitecture: string; readonly guestPlatform: string; readonly engine: "firecracker" | "apple-virtualization" | "hyper-v"; readonly lifecycle: Qualification; readonly fullState: Qualification; readonly images: Qualification; readonly defaultImageDigest: string | null; }
export interface ImageDefaults { readonly environment: Readonly<Record<string, string>>; readonly user: string | null; readonly workingDirectory: string | null; }
export interface ManagementReport { readonly generation: number; readonly identity: { readonly bootId: string; readonly instanceId: string }; readonly observedUnixMillis: number; }
export type ManagementObservation = { readonly kind: "current"; readonly value: ManagementReport } | { readonly kind: "unavailable"; readonly lastKnown: ManagementReport | null };
export interface MachineInspection { readonly id: string; readonly imageDigest: string; readonly resources: Required<ResourceEnvelope>; readonly runtimeConfiguration: RuntimeConfiguration; readonly configurationRevision: number; readonly reservation: "held" | "released"; readonly knownSensitive: boolean; readonly lifecycleIntent: Readonly<Record<string, unknown>>; readonly machine: Readonly<Record<string, unknown>>; readonly management: ManagementObservation; readonly executionDefaults: ImageDefaults; readonly lifetime: Readonly<{ expiresAtUnixMillis: number | null; expirationAction: "stop" | "destroy" }>; readonly lastActivityUnixMillis: number; }
export type NetworkDestination = { readonly kind: "dns"; readonly name: string; readonly includeSubdomains?: boolean; readonly allowPrivateAddresses?: boolean } | { readonly kind: "ip"; readonly cidr: string };
export interface NetworkRule { readonly plane: "named-proxy" | "direct-tcp" | "dns"; readonly destination: NetworkDestination; readonly ports: readonly ({ readonly from: number; readonly to: number } | number)[]; }
export interface NetworkPolicy { readonly rules: readonly NetworkRule[]; }
export interface ExposureSpec { readonly guestAddress?: string; readonly guestPort: number; readonly hostAddress?: string; readonly hostPort?: number; readonly public?: boolean; }
export interface Exposure { readonly id: string; readonly machineId: string; readonly revision: number; readonly spec: { readonly guestAddress: string; readonly guestPort: number; readonly hostAddress: string; readonly hostPort: number; readonly public: boolean }; readonly active: boolean; readonly boundPort: number | null; }
export interface RuntimeConfiguration { readonly network: NetworkPolicy; readonly exposures: readonly Exposure[]; readonly resources: Required<ResourceEnvelope>; }
export interface ResourceUsage { readonly cpuMicros: number | null; readonly memoryCurrent: number | null; readonly memoryPeak: number | null; readonly diskLogicalBytes: number; readonly diskAllocatedBytes: number; readonly ioReadBytes: number | null; readonly ioWriteBytes: number | null; readonly outputRetainedBytes: number; readonly networkRxBytes: number; readonly networkTxBytes: number; readonly networkConnections: number; readonly executionsCurrent: number; readonly complete: boolean; readonly source: string; readonly observedUnixMillis: number; }
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
export interface ImageInspection { readonly digest: string; readonly sourceDigest: string; readonly platform: string; readonly architecture: string; readonly logicalBytes: number; readonly storageBytes: number; readonly provenanceDigest: string; readonly sensitive: boolean; }
export interface ImageReleaseInspection { readonly operationId: string; readonly imageDigest: string; readonly requestDigest: string; readonly cleanupPending: boolean; }
export interface Receipt { readonly machineId: string; readonly generation: number; readonly executionId: string; readonly operationId: string; readonly requestDigest: string; readonly outcome: Readonly<Record<string, unknown>>; readonly output: Readonly<Record<string, unknown>>; readonly cleanupDigest: string; readonly accountingDigest: string; }
export interface ReceiptView { readonly receipt: Receipt; readonly digest: string; }
export interface CaptureCommitment { readonly storeId: string; readonly commitmentId: string; readonly manifestDigest: string; readonly receiptDigest: string; readonly output: Readonly<Record<string, unknown>>; }
export type ReleaseDisposition = { readonly kind: "complete-capture"; readonly commitment: CaptureCommitment } | { readonly kind: "continuing-retention"; readonly pin: string } | { readonly kind: "authorized-loss"; readonly authorization?: string };
export interface ReleaseStatus { readonly requestDigest: string; readonly cleanupPending: boolean; }
export interface MachineEvent { readonly cursor: number; readonly value: Readonly<Record<string, unknown>>; readonly digest: string; }
export interface MachineEventPage { readonly cursor: number; readonly available: number; readonly events: readonly MachineEvent[]; }

export class Sandsurf {
  readonly machines: MachineCollection;
  readonly images: ImageCollection;
  readonly snapshots: SnapshotCollection;
  readonly secrets: SecretCollection;
  readonly operations: SandsurfOperations;
  readonly artifacts: ArtifactCollection;
  readonly #client: NativeHostClient;
  readonly #authorizer: SandsurfAuthorizer | undefined;
  #closed = false;
  private constructor(client: NativeHostClient, authorizer: SandsurfAuthorizer | undefined) { this.#client = client; this.#authorizer = authorizer; this.machines = new MachineCollection(this); this.images = new ImageCollection(this); this.snapshots = new SnapshotCollection(this); this.secrets = new SecretCollection(this); this.operations = new SandsurfOperations(this); this.artifacts = new ArtifactCollection(this); }
  static async open(options: SandsurfOpenOptions): Promise<Sandsurf> { return new Sandsurf(await NativeHostClient.open(resolve(options.directory), options.service ?? "auto"), options.authorizer); }
  async inspect(): Promise<HostInspection> {
    this.#open(); const response = await this.#client.request({ kind: "inspect" });
    if (response.kind !== "inspection" || !record(response.value)) throw protocol("host inspection response");
    return response.value as unknown as HostInspection;
  }
  async close(): Promise<void> { this.#closed = true; await this.#client.close(); }
  async [transport](request: Readonly<Record<string, unknown>>): Promise<Record<string, unknown>> { this.#open(); return this.#client.request(request); }
  async [authorize](change: AuthorityChange): Promise<string> {
    if (this.#authorizer === undefined) throw new SandsurfHostError("authorization", `No authorizer is installed for ${change.kind}`);
    const decision = await this.#authorizer(change);
    if (decision === false) throw new SandsurfHostError("authorization", `${change.kind} was denied`);
    if (decision === true) return childIdentity(change.operationId, `approval-${change.kind}`);
    if (!record(decision) || typeof decision.approvalId !== "string") throw new TypeError("authorizer returned an invalid decision");
    return validateIdentity(decision.approvalId);
  }
  #open(): void { if (this.#closed) throw new SandsurfHostError("client", "Sandsurf client is closed"); }
}

export class SandsurfOperations {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async get(operationId: string, options: { readonly machineId?: string } = {}): Promise<Readonly<Record<string, unknown>> | undefined> {
    const response = await this.#host[transport](options.machineId === undefined
      ? { kind: "get-host-operation", operationId: validateIdentity(operationId) }
      : { kind: "get-operation", operationId: validateIdentity(operationId), machineId: validateIdentity(options.machineId) });
    if (response.kind === "runtime" && record(response.response) && response.response.kind === "operation") {
      return response.response.operation === null ? undefined : record(response.response.operation) ? response.response.operation : (() => { throw protocol("operation record"); })();
    }
    if (response.kind !== "host-operation") throw protocol("host operation response");
    if (response.value === null) return undefined;
    if (!record(response.value)) throw protocol("host operation record");
    return response.value;
  }
}

export class SecretCollection {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async put(id: string, bytes: string | Uint8Array, options: { readonly operationId?: string } = {}): Promise<SecretVersion> {
    const secretId = validateIdentity(id); const operationId = validateIdentity(options.operationId ?? identity("secret")); const value = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
    if (!(value instanceof Uint8Array) || value.byteLength === 0 || value.byteLength > 1024 * 1024) throw new TypeError("secret must contain 1 byte through 1 MiB");
    const version = `v-${sandsurfDigest("secret", { secretId, operationId })}`;
    const approvalId = await this.#host[authorize]({ kind: "secret-delivery", machineId: "host", operationId, request: { secretId, version, bytes: value.byteLength, destination: "host-capability-store" } });
    const response = await this.#host[transport]({ kind: "put-secret", secretId, version, bytes: [...value], operationId, approvalId });
    if (response.kind !== "secret" || !record(response.secret)) throw protocol("secret response");
    return parseSecret(response.secret);
  }
}

export class ImageCollection {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async importOCI(options: ImageImportOptions): Promise<Image> {
    const operationId = validateIdentity(options.operationId ?? identity("image"));
    if (!record(options.recipe)) throw new TypeError("OCI conversion requires an explicit machine-image recipe");
    const recipe = { bootImageDigest: digest(typeof options.recipe.bootImage === "string" ? options.recipe.bootImage : options.recipe.bootImage.id) };
    const platform = options.platform ?? (await this.#host.inspect()).guestPlatform;
    const source = normalizeOciSource(options);
    const approvalId = await this.#host[authorize]({ kind: "image-import", machineId: "host", operationId, request: { source, recipe, platform } });
    const response = await this.#host[transport]({ kind: "import-oci", source, recipe, platform, operationId, approvalId });
    if (response.kind !== "image-import" || !record(response.operation) || !record(response.operation.image)) throw protocol("image import response");
    return new Image(parseImage(response.operation.image));
  }
  async get(digestValue: string): Promise<Image> {
    const response = await this.#host[transport]({ kind: "get-image", digest: digest(digestValue) });
    if (response.kind !== "image" || !record(response.value)) throw protocol("image response");
    return new Image(parseImage(response.value));
  }
  async list(options: { readonly after?: string; readonly maximum?: number } = {}): Promise<readonly Image[]> {
    const response = await this.#host[transport]({ kind: "list-images", after: options.after === undefined ? null : digest(options.after), maximum: options.maximum ?? 100 });
    if (response.kind !== "images" || !Array.isArray(response.values)) throw protocol("image list response");
    return response.values.map((value) => new Image(parseImage(value)));
  }
  async release(image: string | Image, options: { readonly operationId?: string } = {}): Promise<ImageReleaseInspection> {
    const imageDigest = digest(typeof image === "string" ? image : image.id); const operationId = validateIdentity(options.operationId ?? identity("release-image"));
    const approvalId = await this.#host[authorize]({ kind: "image-release", machineId: "host", operationId, request: { imageDigest } });
    const response = await this.#host[transport]({ kind: "release-image", digest: imageDigest, operationId, approvalId });
    if (response.kind !== "image-release" || !record(response.operation)) throw protocol("image release response");
    return { operationId: text(response.operation.operationId), imageDigest: digest(text(response.operation.imageDigest)), requestDigest: digest(text(response.operation.requestDigest)), cleanupPending: response.operation.cleanupPending === true };
  }
}

export class Image {
  readonly id: string;
  readonly inspection: ImageInspection;
  constructor(inspection: ImageInspection) { this.id = inspection.digest; this.inspection = inspection; }
}

export class SnapshotCollection {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async get(id: string): Promise<Snapshot> {
    const response = await this.#host[transport]({ kind: "get-snapshot", snapshotId: validateIdentity(id) });
    if (response.kind !== "snapshot" || !record(response.value)) throw protocol("snapshot response");
    return new Snapshot(this.#host, parseSnapshot(response.value));
  }
  async list(options: { readonly after?: string; readonly maximum?: number } = {}): Promise<readonly Snapshot[]> {
    const response = await this.#host[transport]({ kind: "list-snapshots", after: options.after === undefined ? null : validateIdentity(options.after), maximum: options.maximum ?? 100 });
    if (response.kind !== "snapshots" || !Array.isArray(response.values)) throw protocol("snapshot list response");
    return response.values.map((value) => new Snapshot(this.#host, parseSnapshot(value)));
  }
}

export class Snapshot {
  readonly id: string;
  readonly inspection: SnapshotInspection;
  readonly #host: Sandsurf;
  constructor(host: Sandsurf, inspection: SnapshotInspection) { this.#host = host; this.inspection = inspection; this.id = inspection.id; }
  async fork(options: MachineForkOptions = {}): Promise<Machine> {
    if (this.inspection.phase !== "ready" || this.inspection.kind !== "disk") throw new SandsurfHostError("conflict", "Only a ready disk snapshot can be forked");
    const machineId = validateIdentity(options.id ?? identity("machine")); const operationId = validateIdentity(options.operationId ?? identity("fork")); const resources = normalizeResources(options.resources ?? this.inspection.resources);
    const lifetime = normalizeLifetime(options.lifetime);
    const approvalId = await this.#host[authorize]({ kind: "fork", machineId, operationId, request: { snapshotId: this.id, sourceMachineId: this.inspection.machineId, resources, lifetime } });
    const response = await this.#host[transport]({ kind: "fork-machine", machineId, snapshotId: this.id, resources, lifetime, operationId, approvalId });
    const machine = new Machine(this.#host, machineViewFrom(response));
    return machine;
  }
  async publishImage(options: DerivedImagePublishOptions = {}): Promise<Image> {
    if (this.inspection.phase !== "ready" || this.inspection.kind !== "disk") throw new SandsurfHostError("conflict", "Only a ready disk snapshot can be published");
    const operationId = validateIdentity(options.operationId ?? identity("publish-image"));
    const allowSensitive = options.allowSensitive ?? false;
    const approvalId = await this.#host[authorize]({ kind: "image-publish", machineId: this.inspection.machineId, operationId, request: { snapshotId: this.id, allowSensitive } });
    const response = await this.#host[transport]({ kind: "publish-snapshot-image", snapshotId: this.id, allowSensitive, operationId, approvalId });
    if (response.kind !== "image-import" || !record(response.operation) || !record(response.operation.image)) throw protocol("derived image response");
    return new Image(parseImage(response.operation.image));
  }
}

export class MachineCollection {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async create(options: MachineCreateOptions): Promise<Machine> {
    const machineId = validateIdentity(options.id ?? identity("machine"));
    const operationId = validateIdentity(options.operationId ?? identity("create"));
    digest(options.image); const resources = normalizeResources(options.resources);
    const lifetime = normalizeLifetime(options.lifetime);
    const executionDefaults = normalizeExecutionDefaults(options);
    const approvalId = await this.#host[authorize]({ kind: "machine-create", machineId, operationId, request: { image: options.image, resources, executionDefaults, network: { rules: [] }, lifetime } });
    const response = await this.#host[transport]({ kind: "create-machine", machineId, imageDigest: options.image, resources, executionDefaults, lifetime, operationId, approvalId });
    const machine = new Machine(this.#host, machineViewFrom(response));
    return machine;
  }
  async connect(id: string): Promise<Machine> { return new Machine(this.#host, machineViewFrom(await this.#host[transport]({ kind: "get-machine", machineId: validateIdentity(id) }))); }
  async list(options: { readonly after?: string; readonly maximum?: number } = {}): Promise<readonly Machine[]> {
    const response = await this.#host[transport]({ kind: "list-machines", after: options.after ?? null, maximum: options.maximum ?? 100 });
    if (response.kind !== "machines" || !Array.isArray(response.values)) throw protocol("machine list response");
    return response.values.map((value) => new Machine(this.#host, parseView(value)));
  }
}

export class Machine {
  readonly id: string;
  readonly executions: ExecutionCollection;
  readonly terminals: TerminalCollection;
  readonly fs: MachineFilesystem;
  readonly artifacts: MachineArtifacts;
  readonly events: MachineEvents;
  readonly network: MachineNetwork;
  readonly ports: MachinePorts;
  readonly resources: MachineResources;
  readonly secrets: MachineSecrets;
  readonly snapshots: MachineSnapshots;
  readonly #host: Sandsurf;
  #view: MachineInspection;
  constructor(host: Sandsurf, view: MachineInspection) { this.#host = host; this.#view = view; this.id = view.id; this.executions = new ExecutionCollection(this); this.terminals = new TerminalCollection(this); this.fs = new MachineFilesystem(this); this.artifacts = new MachineArtifacts(this, host); this.events = new MachineEvents(this); this.network = new MachineNetwork(this); this.ports = new MachinePorts(this); this.resources = new MachineResources(this); this.secrets = new MachineSecrets(this); this.snapshots = new MachineSnapshots(this, host); }
  get revision(): number { return this.#view.configurationRevision; }
  get generation(): number | undefined { return this.#view.machine.kind === "current" && record(this.#view.machine.value) ? integer(this.#view.machine.value.generation) : undefined; }
  retainedOutput(pinId: string): PinnedOutput { return new PinnedOutput(this, validateIdentity(pinId)); }
  async inspect(): Promise<MachineInspection> { return this[observe](machineViewFrom(await this.#host[transport]({ kind: "get-machine", machineId: this.id }))); }
  async start(options: MachineLifecycleOptions = {}): Promise<MachineInspection> { return this.#lifecycle("running", options); }
  async powerOff(options: MachineLifecycleOptions = {}): Promise<MachineInspection> { return this.#lifecycle("stopped", options); }
  exec(options: ExecOptions): Promise<ExecResult> { return this.executions.exec(options); }
  execShell(command: string, options: ExecShellOptions = {}): Promise<ExecResult> { return this.executions.execShell(command, options); }
  shell(options: ShellOptions = {}): Promise<Terminal> { return this.terminals.open({ ...options, argv: [options.shell ?? "/bin/sh", "-l"] }); }
  async pause(options: MachineLifecycleOptions = {}): Promise<MachineInspection> { return this.#lifecycle("paused", options); }
  async resume(options: MachineLifecycleOptions = {}): Promise<MachineInspection> { return this.#lifecycle("running", options); }
  async suspend(options: MachineLifecycleOptions = {}): Promise<MachineInspection> { return this.#lifecycle("suspended", options); }
  async destroy(options: MachineLifecycleOptions = {}): Promise<MachineInspection> { return this.#lifecycle("destroyed", options); }
  get [observed](): MachineInspection { return this.#view; }
  [observe](view: MachineInspection): MachineInspection {
    if (view.id !== this.id) throw protocol("host response belongs to another machine");
    const oldNative = nativeObservationOrder(this.#view.machine);
    const newNative = nativeObservationOrder(view.machine);
    const retainNative = oldNative[0] > newNative[0] ||
      (oldNative[0] === newNative[0] && oldNative[1] > newNative[1]);
    const authority = view.configurationRevision >= this.#view.configurationRevision ? view : this.#view;
    this.#view = { ...authority,
      machine: retainNative ? this.#view.machine : view.machine,
      management: retainNative ? this.#view.management : view.management };
    return view;
  }
  async [dispatchGuest](request: Readonly<Record<string, unknown>>, operationId: string, precondition: MachineGenerationPrecondition = {}): Promise<Record<string, unknown>> {
    const authority = resolveGenerationPrecondition(this, precondition);
    const response = await this.#host[transport]({ kind: "dispatch-guest", machineId: this.id, generation: authority.expectedGeneration, operationId, request });
    if (response.kind !== "dispatch" || !record(response.operation)) throw protocol("workload dispatch response");
    const delivery = text(response.operation.delivery);
    if (delivery !== "applied") {
      if (delivery !== "not-applied" && delivery !== "unknown") throw protocol("workload dispatch delivery");
      throw new SandsurfHostError(delivery === "unknown" ? "ambiguous" : "not-applied", `Workload operation ${operationId} was ${delivery}`);
    }
    return response.operation;
  }
  async [queryGuest](request: Readonly<Record<string, unknown>>, precondition: MachineGenerationPrecondition = {}): Promise<Record<string, unknown>> {
    const generation = expectedCounter(precondition.expectedGeneration, "expected generation") ?? currentMachine(this.#view).generation;
    const response = await this.#host[transport]({ kind: "guest", machineId: this.id, generation, request });
    if (response.kind !== "guest" || !record(response.response)) throw protocol("guest response");
    if (response.response.kind === "error") throw new SandsurfHostError(text(response.response.code), text(response.response.message));
    return response.response;
  }
  async [transport](request: Readonly<Record<string, unknown>>): Promise<Record<string, unknown>> { return this.#host[transport](request); }
  async [authorize](change: AuthorityChange): Promise<string> { return this.#host[authorize](change); }
  async #lifecycle(desired: DesiredMachineState, options: MachineLifecycleOptions): Promise<MachineInspection> {
    const operationId = validateIdentity(options.operationId ?? identity(desired)); const expectedRevision = await resolveRevisionPrecondition(this, options.expectedRevision); const approvalId = await this.#host[authorize]({ kind: "lifecycle", machineId: this.id, operationId, request: { desired, expectedRevision } });
    return this[observe](machineViewFrom(await this.#host[transport]({ kind: "lifecycle", machineId: this.id, operationId, expectedRevision, desired, approvalId })));
  }
}

export class MachineSnapshots {
  readonly #machine: Machine;
  readonly #host: Sandsurf;
  constructor(machine: Machine, host: Sandsurf) { this.#machine = machine; this.#host = host; }
  async create(options: SnapshotCreateOptions = {}): Promise<Snapshot> {
    const id = validateIdentity(options.id ?? identity("snapshot")); const operationId = validateIdentity(options.operationId ?? identity("snapshot")); const authority = await resolveMachinePreconditions(this.#machine, options); const kind = options.kind ?? "disk";
    if (kind !== "disk" && kind !== "full") throw new TypeError("snapshot kind is invalid");
    const parent = options.parent === undefined ? null : validateIdentity(options.parent); const request = { id, operationId, machineId: this.#machine.id, expectedGeneration: authority.expectedGeneration, expectedRevision: authority.expectedRevision, kind, parent };
    const approvalId = await this.#machine[authorize]({ kind: "snapshot", machineId: this.#machine.id, operationId, request });
    const response = await this.#machine[transport]({ kind: "create-snapshot", request, approvalId });
    if (response.kind !== "snapshot" || !record(response.value)) throw protocol("snapshot response");
    return new Snapshot(this.#host, parseSnapshot(response.value));
  }
  async rollback(snapshotId: string, options: MachineRevisionPrecondition & { readonly operationId?: string } = {}): Promise<Readonly<Record<string, unknown>>> {
    const id = validateIdentity(snapshotId); const operationId = validateIdentity(options.operationId ?? identity("rollback")); const expectedRevision = await resolveRevisionPrecondition(this.#machine, options.expectedRevision);
    const approvalId = await this.#machine[authorize]({ kind: "snapshot", machineId: this.#machine.id, operationId, request: { action: "rollback", snapshotId: id, expectedRevision } });
    const response = await this.#machine[transport]({ kind: "rollback-filesystem", machineId: this.#machine.id, snapshotId: id, operationId, expectedRevision, approvalId });
    if (response.kind !== "rollback" || !record(response.value)) throw protocol("rollback response");
    return response.value;
  }
}

export class MachineNetwork {
  readonly #machine: Machine;
  constructor(machine: Machine) { this.#machine = machine; }
  async configure(policy: NetworkPolicy, options: MachineRevisionPrecondition & { readonly operationId?: string } = {}): Promise<RuntimeConfiguration> {
    const normalized = normalizeNetworkPolicy(policy); const operationId = validateIdentity(options.operationId ?? identity("network")); const expectedRevision = await resolveRevisionPrecondition(this.#machine, options.expectedRevision);
    const approvalId = await this.#machine[authorize]({ kind: "network-access", machineId: this.#machine.id, operationId, request: { expectedRevision, policy: normalized } });
    const response = await this.#machine[transport]({ kind: "set-network-policy", machineId: this.#machine.id, operationId, expectedRevision, policy: normalized, approvalId });
    if (response.kind !== "configuration" || !record(response.machine)) throw protocol("network configuration response");
    return this.#machine[observe](parseView(response.machine)).runtimeConfiguration;
  }
  async denyAll(options: MachineRevisionPrecondition & { readonly operationId?: string } = {}): Promise<RuntimeConfiguration> { return this.configure({ rules: [] }, options); }
  async inspect(): Promise<NetworkPolicy> { return (await this.#machine.inspect()).runtimeConfiguration.network; }
}

export class MachinePorts {
  readonly #machine: Machine;
  constructor(machine: Machine) { this.#machine = machine; }
  async expose(spec: ExposureSpec, options: MachineRevisionPrecondition & { readonly id?: string; readonly operationId?: string } = {}): Promise<Exposure> {
    const exposureId = validateIdentity(options.id ?? identity("exposure")); const operationId = validateIdentity(options.operationId ?? identity("expose")); const expectedRevision = await resolveRevisionPrecondition(this.#machine, options.expectedRevision);
    const normalized = normalizeExposure(spec);
    const approvalId = await this.#machine[authorize]({ kind: "port-exposure", machineId: this.#machine.id, operationId, request: { exposureId, expectedRevision, spec: normalized, active: true } });
    const response = await this.#machine[transport]({ kind: "set-exposure", machineId: this.#machine.id, operationId, expectedRevision, exposureId, spec: normalized, active: true, approvalId });
    if (response.kind !== "exposure" || !record(response.exposure) || !record(response.machine)) throw protocol("port exposure response");
    this.#machine[observe](parseView(response.machine));
    return parseExposure(response.exposure);
  }
  async revoke(id: string, options: MachineRevisionPrecondition & { readonly operationId?: string } = {}): Promise<Exposure> {
    const exposureId = validateIdentity(id); const operationId = validateIdentity(options.operationId ?? identity("unexpose")); const view = await this.#machine.inspect(); const expectedRevision = expectedCounter(options.expectedRevision, "expected revision") ?? view.configurationRevision; const existing = view.runtimeConfiguration.exposures.find((value) => value.id === exposureId);
    if (existing === undefined) throw new SandsurfHostError("missing", `Exposure ${exposureId} does not exist`);
    const approvalId = await this.#machine[authorize]({ kind: "port-exposure", machineId: this.#machine.id, operationId, request: { exposureId, expectedRevision, spec: existing.spec, active: false } });
    const response = await this.#machine[transport]({ kind: "set-exposure", machineId: this.#machine.id, operationId, expectedRevision, exposureId, spec: existing.spec, active: false, approvalId });
    if (response.kind !== "exposure" || !record(response.exposure) || !record(response.machine)) throw protocol("port exposure revocation response");
    this.#machine[observe](parseView(response.machine));
    return parseExposure(response.exposure);
  }
  async list(): Promise<readonly Exposure[]> { return (await this.#machine.inspect()).runtimeConfiguration.exposures; }
}

export class MachineResources {
  readonly #machine: Machine;
  constructor(machine: Machine) { this.#machine = machine; }
  async usage(): Promise<ResourceUsage> {
    const response = await this.#machine[transport]({ kind: "get-usage", machineId: this.#machine.id });
    if (response.kind !== "usage" || !record(response.usage)) throw protocol("resource usage response");
    return parseUsage(response.usage);
  }
  async update(resources: ResourceEnvelope, options: MachineRevisionPrecondition & { readonly operationId?: string } = {}): Promise<MachineInspection> {
    const operationId = validateIdentity(options.operationId ?? identity("resources")); const expectedRevision = await resolveRevisionPrecondition(this.#machine, options.expectedRevision); const normalized = normalizeResources(resources);
    const approvalId = await this.#machine[authorize]({ kind: "resource-increase", machineId: this.#machine.id, operationId, request: { expectedRevision, resources: normalized } });
    const response = await this.#machine[transport]({ kind: "update-resources", machineId: this.#machine.id, operationId, expectedRevision, resources: normalized, approvalId });
    if (response.kind !== "configuration" || !record(response.machine)) throw protocol("resource update response");
    return this.#machine[observe](parseView(response.machine));
  }
}

export class MachineSecrets {
  readonly #machine: Machine;
  constructor(machine: Machine) { this.#machine = machine; }
  async deliver(secret: SecretVersion, options: MachineRevisionPrecondition & { readonly path?: string | Uint8Array; readonly mode?: number; readonly environment?: string; readonly executionId?: string; readonly lifetime?: "process" | "machine" | "until-revoked"; readonly operationId?: string } = {}): Promise<SecretDeliveryResult> {
    const parsed = parseSecret(secret as unknown as Record<string, unknown>); const operationId = validateIdentity(options.operationId ?? identity("deliver")); const expectedRevision = await resolveRevisionPrecondition(this.#machine, options.expectedRevision); let destination: Readonly<Record<string, unknown>>;
    if (options.environment !== undefined) { if (!/^[A-Za-z0-9_]{1,4096}$/u.test(options.environment)) throw new TypeError("secret environment name is malformed"); destination = { kind: "environment", name: options.environment }; }
    else { const path = options.path ?? `/run/sandsurf-secrets/${parsed.id}`; destination = { kind: "file", path: [...createSandsurfGuestPath(path)], mode: options.mode ?? 0o600 }; }
    const lifetime = options.lifetime ?? (options.executionId === undefined ? "machine" : "process"); const executionId = options.executionId === undefined ? null : validateIdentity(options.executionId); const delivery = { secret: parsed, destination, lifetime, executionId };
    const approvalId = await this.#machine[authorize]({ kind: "secret-delivery", machineId: this.#machine.id, operationId, request: { expectedRevision, delivery } });
    const response = await this.#machine[transport]({ kind: "deliver-secret", machineId: this.#machine.id, operationId, expectedRevision, delivery, approvalId });
    if (response.kind !== "secret-delivery" || !record(response.delivery) || !record(response.delivery.delivery) || !record(response.delivery.delivery.secret)) throw protocol("secret delivery response");
    const disclosure = response.delivery.disclosure;
    if (disclosure !== "not-sent" && disclosure !== "possible" && disclosure !== "guest-reported-received") throw protocol("secret disclosure state");
    return { operationId: validateIdentity(text(response.delivery.operationId)), machineId: validateIdentity(text(response.delivery.machineId)), secret: parseSecret(response.delivery.delivery.secret), disclosure, revoked: response.delivery.revoked === true };
  }
  async revoke(secret: SecretVersion, options: MachineRevisionPrecondition & { readonly terminateRecipients?: boolean; readonly operationId?: string } = {}): Promise<SecretRevocation> {
    const parsed = parseSecret(secret as unknown as Record<string, unknown>); const operationId = validateIdentity(options.operationId ?? identity("revoke-secret")); const expectedRevision = await resolveRevisionPrecondition(this.#machine, options.expectedRevision); const terminateRecipients = options.terminateRecipients ?? true;
    const approvalId = await this.#machine[authorize]({ kind: "secret-revocation", machineId: this.#machine.id, operationId, request: { expectedRevision, secret: parsed, terminateRecipients } });
    const response = await this.#machine[transport]({ kind: "revoke-secret", machineId: this.#machine.id, operationId, expectedRevision, secret: parsed, terminateRecipients, approvalId });
    if (response.kind !== "secret-revocation" || !record(response.revocation)) throw protocol("secret revocation response");
    return parseSecretRevocation(response.revocation);
  }
}


export class MachineEvents {
  readonly #machine: Machine;
  constructor(machine: Machine) { this.#machine = machine; }
  async read(options: { readonly after?: number; readonly maximum?: number } = {}): Promise<MachineEventPage> {
    const after = options.after ?? 0; const maximum = options.maximum ?? 256;
    if (!Number.isSafeInteger(after) || after < 0) throw new TypeError("event cursor must be a non-negative safe integer");
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 256) throw new TypeError("event page maximum must be 1 through 256");
    const response = await this.#machine[transport]({ kind: "list-events", machineId: this.#machine.id, after, maximum });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "events" || !record(response.response.page) || !Array.isArray(response.response.page.events)) throw protocol("event page response");
    const page = response.response.page; const events = page.events;
    if (!Array.isArray(events)) throw protocol("runtime events");
    return {
      cursor: integer(page.cursor),
      available: integer(page.available),
      events: Object.freeze(events.map((event: unknown) => {
        if (!record(event) || !record(event.value)) throw protocol("runtime event");
        return Object.freeze({ cursor: integer(event.cursor), value: Object.freeze({ ...event.value }), digest: digest(text(event.digest)) });
      })),
    };
  }
  async *follow(options: { readonly after?: number; readonly maximum?: number; readonly pollMs?: number; readonly signal?: AbortSignal } = {}): AsyncGenerator<MachineEvent, void> {
    let cursor = options.after ?? 0; const poll = options.pollMs ?? 50;
    if (!Number.isSafeInteger(poll) || poll < 1 || poll > 60_000) throw new TypeError("event poll interval must be 1 through 60000 milliseconds");
    for (;;) {
      if (options.signal?.aborted === true) return;
      const page = await this.read({ after: cursor, maximum: options.maximum ?? 256 });
      for (const event of page.events) { cursor = event.cursor; yield event; }
      if (page.events.length === 0) await new Promise((done) => setTimeout(done, poll));
    }
  }
}

export interface TerminalSize { readonly columns: number; readonly rows: number; readonly pixelWidth?: number; readonly pixelHeight?: number; }
export interface ExecutionOperationOptions extends MachineGenerationPrecondition { readonly operationId?: string; }
export interface ExecutionSignalOptions extends ExecutionOperationOptions { readonly group?: boolean; }
export interface ExecutionTerminateOptions extends ExecutionOperationOptions { readonly graceMillis?: number; }
export interface SpawnOptions extends MachineGenerationPrecondition { readonly operationId?: string; readonly executionId?: string; readonly argv: readonly string[]; readonly cwd?: string; readonly environment?: Readonly<Record<string, string>>; readonly user?: string; readonly stdio?: "pipes" | "terminal"; readonly terminalSize?: TerminalSize; readonly activeDeadlineMs?: number; readonly elapsedDeadlineUnixMs?: number; readonly outputBytes?: number; }
export type ExecOptions = SpawnOptions & { readonly signal?: AbortSignal; readonly pollMs?: number };
export type ShellOptions = Omit<SpawnOptions, "argv"> & { readonly shell?: string };
export type ExecShellOptions = Omit<ExecOptions, "argv"> & { readonly shell?: string };
export interface ExecResult { readonly process: Execution; readonly inspection: ExecutionInspection; }
export interface ExecutionInspection { readonly request: Readonly<Record<string, unknown>>; readonly guestPid: number; readonly state: Readonly<Record<string, unknown>>; readonly lineage: Readonly<Record<string, unknown>> | null; }
export type ExecutionObservation = { readonly kind: "current"; readonly value: ExecutionInspection } | { readonly kind: "unavailable"; readonly lastKnown: ExecutionInspection | null };

export class ExecutionCollection {
  readonly #machine: Machine;
  constructor(machine: Machine) { this.#machine = machine; }
  async start(options: SpawnOptions): Promise<Execution> {
    const operationId = validateIdentity(options.operationId ?? identity("spawn")); const executionId = validateIdentity(options.executionId ?? identity("process"));
    const view = this.#machine[observed]; const authority = { expectedGeneration: expectedCounter(options.expectedGeneration, "expected generation") ?? currentMachine(view).generation }; const stdio = options.stdio ?? "pipes";
    const terminalSize = stdio === "terminal" ? { columns: options.terminalSize?.columns ?? 80, rows: options.terminalSize?.rows ?? 24, pixelWidth: options.terminalSize?.pixelWidth ?? 0, pixelHeight: options.terminalSize?.pixelHeight ?? 0 } : null;
    const user = options.user ?? view.executionDefaults.user ?? "root";
    const activeDeadlineMillis = options.activeDeadlineMs ?? null; if (activeDeadlineMillis !== null && (!Number.isSafeInteger(activeDeadlineMillis) || activeDeadlineMillis <= 0 || activeDeadlineMillis > 30 * 24 * 60 * 60 * 1000)) throw new TypeError("active process deadline must be a positive safe integer no greater than 30 days");
    const elapsedDeadlineUnixMillis = options.elapsedDeadlineUnixMs ?? null; if (elapsedDeadlineUnixMillis !== null && (!Number.isSafeInteger(elapsedDeadlineUnixMillis) || elapsedDeadlineUnixMillis <= 0)) throw new TypeError("elapsed process deadline must be a positive Unix millisecond value");
    const outputBudget = integer(view.resources.outputBytes);
    const outputBytes = options.outputBytes ?? Math.max(1, Math.min(16 * 1024 * 1024, Math.floor(outputBudget / 8)));
    if (!Number.isSafeInteger(outputBytes) || outputBytes < 1 || outputBytes > outputBudget) throw new TypeError("process output reservation must fit the Machine output budget");
    await this.#machine[dispatchGuest]({ kind: "spawn", request: { machineId: this.#machine.id, generation: authority.expectedGeneration, executionId, operationId, argv: [...options.argv], cwd: options.cwd ?? view.executionDefaults.workingDirectory ?? "/", environment: { ...view.executionDefaults.environment, ...(options.environment ?? {}) }, user, stdio, terminalSize, activeDeadlineMillis, elapsedDeadlineUnixMillis, outputBytes } }, operationId, authority);
    return new Execution(this.#machine, executionId, authority.expectedGeneration);
  }
  async exec(options: ExecOptions): Promise<ExecResult> {
    const { signal, pollMs, ...spawn } = options;
    const process = await this.start(spawn);
    return { process, inspection: await process.waitLeader({ ...(signal === undefined ? {} : { signal }), ...(pollMs === undefined ? {} : { pollMs }) }) };
  }
  spawnShell(command: string, options: ShellOptions = {}): Promise<Execution> {
    if (command.length === 0 || command.length > 1024 * 1024) throw new TypeError("shell command is empty or oversized");
    const { shell = "/bin/sh", ...spawn } = options;
    return this.start({ ...spawn, argv: [shell, "-lc", command] });
  }
  execShell(command: string, options: ExecShellOptions = {}): Promise<ExecResult> {
    if (command.length === 0 || command.length > 1024 * 1024) throw new TypeError("shell command is empty or oversized");
    const { shell = "/bin/sh", ...exec } = options;
    return this.exec({ ...exec, argv: [shell, "-lc", command] });
  }
  async get(id: string): Promise<Execution> {
    const executionId = validateIdentity(id);
    const response = await this.#machine[transport]({ kind: "get-process", machineId: this.#machine.id, executionId });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "process" || !record(response.response.request)) throw protocol("execution response");
    if (response.response.request.executionId !== executionId || response.response.request.machineId !== this.#machine.id) throw protocol("execution reservation identity");
    return new Execution(this.#machine, executionId, integer(response.response.request.generation));
  }
  async list(): Promise<readonly ExecutionObservation[]> {
    const response = await this.#machine[transport]({ kind: "list-processes", machineId: this.#machine.id });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "processes" || !Array.isArray(response.response.processes)) throw protocol("process list response");
    return response.response.processes.map(parseExecutionObservation);
  }
}

export type TerminalOpenOptions = Omit<SpawnOptions, "stdio" | "terminalSize"> & { readonly terminalSize?: TerminalSize; readonly inputLeaseId?: string; readonly inputLeaseOperationId?: string };

export class TerminalCollection {
  readonly #machine: Machine;
  constructor(machine: Machine) { this.#machine = machine; }
  async open(options: TerminalOpenOptions): Promise<Terminal> {
    const { inputLeaseId, inputLeaseOperationId, ...spawn } = options;
    const operationId = validateIdentity(spawn.operationId ?? identity("spawn-terminal")); const executionId = validateIdentity(spawn.executionId ?? identity("terminal"));
    const process = await this.#machine.executions.start({ ...spawn, operationId, executionId, stdio: "terminal", ...(options.terminalSize === undefined ? {} : { terminalSize: options.terminalSize }) });
    const terminal = new Terminal(process);
    await terminal.acquireInput({ leaseId: inputLeaseId ?? childIdentity(operationId, "input-lease"), operationId: inputLeaseOperationId ?? childIdentity(operationId, "acquire-input"), ...(options.expectedGeneration === undefined ? {} : { expectedGeneration: options.expectedGeneration }) });
    return terminal;
  }
  async get(id: string): Promise<Terminal> {
    const executionId = validateIdentity(id);
    const response = await this.#machine[transport]({ kind: "get-process", machineId: this.#machine.id, executionId });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "process" || !record(response.response.request)) throw protocol("terminal response");
    const request = response.response.request;
    if (request.executionId !== executionId || request.machineId !== this.#machine.id) throw protocol("terminal reservation identity");
    if (request.stdio !== "terminal") throw new SandsurfHostError("conflict", `Process ${executionId} is not a terminal`);
    return new Terminal(new Execution(this.#machine, executionId, integer(request.generation)));
  }
}

export class Terminal {
  readonly id: string;
  readonly input: ExecutionInput;
  readonly output: ExecutionOutput;
  readonly process: Execution;
  #attached = true;
  #inputLeaseId: string | undefined;
  constructor(process: Execution) { this.process = process; this.id = process.id; this.output = process.output; this.input = new ExecutionInput(process, () => { this.#requireAttached(); if (this.#inputLeaseId === undefined) throw new SandsurfHostError("conflict", `Terminal ${this.id} has no input lease`); return this.#inputLeaseId; }); }
  async acquireInput(options: ExecutionOperationOptions & { readonly leaseId?: string } = {}): Promise<string> { this.#requireAttached(); const id = validateIdentity(options.leaseId ?? identity("terminal-input")); await this.process.acquireTerminalInput(id, options); this.#inputLeaseId = id; return id; }
  async releaseInput(options: ExecutionOperationOptions = {}): Promise<void> { this.#requireAttached(); if (this.#inputLeaseId !== undefined) { const lease = this.#inputLeaseId; await this.process.releaseTerminalInput(lease, options); this.#inputLeaseId = undefined; } }
  async detach(options: MachineGenerationPrecondition & { readonly releaseInputOperationId?: string } = {}): Promise<void> { if (this.#attached) { await this.releaseInput({ ...(options.releaseInputOperationId === undefined ? {} : { operationId: options.releaseInputOperationId }), ...(options.expectedGeneration === undefined ? {} : { expectedGeneration: options.expectedGeneration }) }); this.#attached = false; } }
  inspect(): Promise<ExecutionObservation> { this.#requireAttached(); return this.process.inspect(); }
  waitLeader(options: { readonly pollMs?: number; readonly signal?: AbortSignal } = {}): Promise<ExecutionInspection> { this.#requireAttached(); return this.process.waitLeader(options); }
  waitCapture(options: { readonly pollMs?: number; readonly signal?: AbortSignal } = {}): Promise<ExecutionInspection> { this.#requireAttached(); return this.process.waitCapture(options); }
  resize(size: TerminalSize, options: ExecutionOperationOptions = {}): Promise<void> { this.#requireAttached(); return this.process.resize(size, options); }
  signal(signal: number, options: ExecutionSignalOptions = {}): Promise<void> { this.#requireAttached(); return this.process.signal(signal, options); }
  terminate(options: ExecutionTerminateOptions = {}): Promise<void> { this.#requireAttached(); return this.process.terminate(options); }
  #requireAttached(): void { if (!this.#attached) throw new SandsurfHostError("client", `Terminal ${this.id} is detached`); }
}

export interface OutputChunk { readonly cursor: number; readonly stream: "stdout" | "stderr" | "terminal"; readonly bytes: Uint8Array; readonly digest: string; }
export interface OutputPage { readonly after: number; readonly available: number; readonly chunks: readonly OutputChunk[]; readonly requiredBytes?: number; }

const executionMachines = new WeakMap<Execution, Machine>();
export class Execution {
  readonly id: string; readonly generation: number; readonly input: ExecutionInput; readonly output: ExecutionOutput; readonly #machine: Machine;
  constructor(machine: Machine, id: string, generation: number) { this.#machine = machine; this.id = id; this.generation = expectedCounter(generation, "execution generation")!; executionMachines.set(this, machine); this.input = new ExecutionInput(this); this.output = new ExecutionOutput(this, machine); }
  [executionFence](options: ExecutionOperationOptions): ExecutionOperationOptions {
    if (options.expectedGeneration !== undefined && options.expectedGeneration !== this.generation) throw new SandsurfHostError("stale-generation", "An execution handle cannot be rebound to another generation");
    return { ...options, expectedGeneration: this.generation };
  }
  async inspect(): Promise<ExecutionObservation> { const response = await this.#machine[transport]({ kind: "get-process", machineId: this.#machine.id, executionId: this.id }); if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "process") throw protocol("process response"); if (response.response.process === null) throw new SandsurfHostError("missing", `Process ${this.id} does not exist`); return parseExecutionObservation(response.response.process); }
  waitLeader(options: { readonly pollMs?: number; readonly signal?: AbortSignal } = {}): Promise<ExecutionInspection> { return this.#wait("leader", options); }
  waitCapture(options: { readonly pollMs?: number; readonly signal?: AbortSignal } = {}): Promise<ExecutionInspection> { return this.#wait("capture", options); }
  async #wait(boundaryKind: "leader" | "capture", options: { readonly pollMs?: number; readonly signal?: AbortSignal }): Promise<ExecutionInspection> {
    if (options.signal?.aborted === true) throw options.signal.reason;
    const boundary = await this.#machine.events.read({ maximum: 1 });
    const observed = await this.inspect();
    let terminal: ExecutionInspection | undefined;
    const complete = async (value: ExecutionInspection): Promise<boolean> => {
      if (value.state.kind === "running" || (boundaryKind === "capture" && value.state.kind === "draining")) return false;
      if (boundaryKind === "leader" || value.state.kind === "unknown") return true;
      terminal = value;
      const receipt = await this.receipt();
      if (receipt === undefined) return false;
      if (receipt.receipt.executionId !== this.id || receipt.receipt.generation !== this.generation ||
          !record(value.state.output) || !record(receipt.receipt.output) ||
          receipt.receipt.output.finalCursor !== value.state.output.finalCursor ||
          receipt.receipt.output.finalHash !== value.state.output.finalHash) throw protocol("capture receipt disagrees with completed process");
      return true;
    };
    if (observed.kind === "current" && observed.value.request.generation === this.generation && await complete(observed.value)) return observed.value;
    for await (const event of this.#machine.events.follow({ after: boundary.available, ...(options.pollMs === undefined ? {} : { pollMs: options.pollMs }), ...(options.signal === undefined ? {} : { signal: options.signal }) })) {
      if (boundaryKind === "capture" && terminal !== undefined && event.value.kind === "receipt" && event.value.executionId === this.id && await complete(terminal)) return terminal;
      if (event.value.kind !== "process" || !record(event.value.process)) continue;
      const process = parseProcess(event.value.process);
      if (process.request.executionId === this.id && process.request.generation === this.generation && await complete(process)) return process;
    }
    if (options.signal !== undefined) throw options.signal.reason;
    throw new SandsurfHostError("unavailable", `Process ${this.id} event stream ended`);
  }
  async receipt(): Promise<ReceiptView | undefined> {
    const response = await this.#machine[transport]({ kind: "get-receipt", machineId: this.#machine.id, executionId: this.id });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "receipt") throw protocol("receipt response");
    if (response.response.receipt === null && response.response.digest === null) return undefined;
    if (!record(response.response.receipt) || typeof response.response.digest !== "string") throw protocol("receipt record");
    return { receipt: response.response.receipt as unknown as Receipt, digest: digest(response.response.digest) };
  }
  async acknowledge(receiptDigest: string, options: { readonly operationId?: string } = {}): Promise<void> { await this.#evidenceCommand("acknowledge-receipt", { receiptDigest: digest(receiptDigest) }, validateIdentity(options.operationId ?? identity("acknowledge"))); }
  async pin(pinId: string, receiptDigest: string, options: { readonly operationId?: string } = {}): Promise<PinnedOutput> { const id = validateIdentity(pinId); await this.#evidenceCommand("pin-evidence", { pinId: id, receiptDigest: digest(receiptDigest) }, validateIdentity(options.operationId ?? identity("pin"))); return new PinnedOutput(this.#machine, id); }
  async release(receipt: ReceiptView, disposition: ReleaseDisposition, options: { readonly operationId?: string } = {}): Promise<ReleaseStatus> {
    const operationId = validateIdentity(options.operationId ?? identity("release-evidence"));
    let lossApprovalId: string | null = null; let normalized: Readonly<Record<string, unknown>>;
    if (disposition.kind === "complete-capture") normalized = { kind: disposition.kind, commitment: disposition.commitment };
    else if (disposition.kind === "continuing-retention") normalized = { kind: disposition.kind, pin: validateIdentity(disposition.pin) };
    else { const lossOperationId = childIdentity(operationId, "loss-authorization"); lossApprovalId = disposition.authorization === undefined ? await this.#machine[authorize]({ kind: "evidence-loss", machineId: this.#machine.id, operationId: lossOperationId, request: { executionId: this.id, receiptDigest: receipt.digest, output: receipt.receipt.output } }) : validateIdentity(disposition.authorization); normalized = { kind: disposition.kind, authorization: lossApprovalId }; }
    const response = await this.#machine[transport]({ kind: "release-evidence", machineId: this.#machine.id, executionId: this.id, request: { operationId, receiptDigest: receipt.digest, output: receipt.receipt.output, disposition: normalized }, lossApprovalId });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "release" || !record(response.response.status)) throw protocol("release response");
    return parseReleaseStatus(response.response.status);
  }
  async cleanupReleased(requestDigest: string): Promise<ReleaseStatus> {
    const response = await this.#machine[transport]({ kind: "cleanup-released-evidence", machineId: this.#machine.id, executionId: this.id, requestDigest: digest(requestDigest) });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "release" || !record(response.response.status)) throw protocol("release cleanup response");
    return parseReleaseStatus(response.response.status);
  }
  async acquireTerminalInput(terminalLeaseId: string, options: ExecutionOperationOptions = {}): Promise<void> { await this.#machine[dispatchGuest]({ kind: "acquire-terminal-input", executionId: this.id, terminalLeaseId: validateIdentity(terminalLeaseId) }, validateIdentity(options.operationId ?? identity("acquire-input")), this[executionFence](options)); }
  async releaseTerminalInput(terminalLeaseId: string, options: ExecutionOperationOptions = {}): Promise<void> { await this.#machine[dispatchGuest]({ kind: "release-terminal-input", executionId: this.id, terminalLeaseId: validateIdentity(terminalLeaseId) }, validateIdentity(options.operationId ?? identity("release-input")), this[executionFence](options)); }
  async signal(signal: number, options: ExecutionSignalOptions = {}): Promise<void> { await this.#machine[dispatchGuest]({ kind: "signal", executionId: this.id, signal, group: options.group ?? true }, validateIdentity(options.operationId ?? identity("signal")), this[executionFence](options)); }
  async terminate(options: ExecutionTerminateOptions = {}): Promise<void> { await this.#machine[dispatchGuest]({ kind: "terminate", executionId: this.id, graceMillis: options.graceMillis ?? 1000 }, validateIdentity(options.operationId ?? identity("terminate")), this[executionFence](options)); }
  async resize(size: TerminalSize, options: ExecutionOperationOptions = {}): Promise<void> { await this.#machine[dispatchGuest]({ kind: "resize-terminal", executionId: this.id, size: { columns: size.columns, rows: size.rows, pixelWidth: size.pixelWidth ?? 0, pixelHeight: size.pixelHeight ?? 0 } }, validateIdentity(options.operationId ?? identity("resize")), this[executionFence](options)); }
  async #evidenceCommand(kind: "acknowledge-receipt" | "pin-evidence", fields: Readonly<Record<string, unknown>>, operationId: string): Promise<void> {
    const response = await this.#machine[transport]({ kind, machineId: this.#machine.id, executionId: this.id, operationId, ...fields });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "complete") throw protocol("evidence command response");
  }
}

export class ExecutionInput {
  readonly #process: Execution;
  readonly #machine: Machine;
  readonly #terminalLease: (() => string) | undefined;
  constructor(process: Execution, terminalLease?: () => string) { const machine = executionMachines.get(process); if (machine === undefined) throw new TypeError("Process input requires a Sandsurf process handle"); this.#process = process; this.#machine = machine; this.#terminalLease = terminalLease; }
  async write(bytes: Uint8Array, options: ExecutionOperationOptions = {}): Promise<void> { const terminalLeaseId = this.#terminalLease?.() ?? null; await this.#machine[dispatchGuest]({ kind: "write-input", executionId: this.#process.id, terminalLeaseId: terminalLeaseId === null ? null : validateIdentity(terminalLeaseId), bytes: [...bytes] }, validateIdentity(options.operationId ?? identity("input")), this.#process[executionFence](options)); }
  async close(options: ExecutionOperationOptions = {}): Promise<void> { const terminalLeaseId = this.#terminalLease?.() ?? null; await this.#machine[dispatchGuest]({ kind: "close-input", executionId: this.#process.id, terminalLeaseId: terminalLeaseId === null ? null : validateIdentity(terminalLeaseId) }, validateIdentity(options.operationId ?? identity("close")), this.#process[executionFence](options)); }
}

export class ExecutionOutput {
  readonly #process: Execution;
  readonly #machine: Machine;
  constructor(process: Execution, machine: Machine) { this.#process = process; this.#machine = machine; }
  async read(options: { readonly after?: number; readonly maximum?: number } = {}): Promise<OutputPage> { const { after, maximum } = normalizeOutputRead(options); const response = await this.#machine[transport]({ kind: "read-evidence", machineId: this.#machine.id, executionId: this.#process.id, after, maximum }); if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "output" || !record(response.response.page) || !Array.isArray(response.response.page.chunks)) throw protocol("output response"); return parseEvidencePage(response.response.page); }
  async *follow(options: { readonly after?: number; readonly maximum?: number; readonly pollMs?: number; readonly signal?: AbortSignal } = {}): AsyncGenerator<OutputChunk, void, void> {
    let cursor = options.after ?? 0;
    for (;;) {
      if (options.signal?.aborted === true) throw options.signal.reason;
      const boundary = await this.#machine.events.read({ maximum: 1 });
      const page = await this.read({ after: cursor, ...(options.maximum === undefined ? {} : { maximum: options.maximum }) });
      for (const chunk of page.chunks) { cursor = chunk.cursor + chunk.bytes.byteLength; yield chunk; }
      const receipt = await this.#process.receipt();
      if (receipt !== undefined && cursor >= integer(receipt.receipt.output.finalCursor)) return;
      if (cursor < page.available || page.chunks.length > 0) continue;
      let changed = false;
      for await (const event of this.#machine.events.follow({ after: boundary.available, ...(options.pollMs === undefined ? {} : { pollMs: options.pollMs }), ...(options.signal === undefined ? {} : { signal: options.signal }) })) {
        if (!runtimeEventBelongsToProcess(event, this.#process.id)) continue;
        changed = true;
        break;
      }
      if (!changed) {
        if (options.signal !== undefined) throw options.signal.reason;
        throw new SandsurfHostError("unavailable", `Process ${this.#process.id} event stream ended`);
      }
    }
  }
}

export class PinnedOutput {
  readonly id: string; readonly #machine: Machine;
  constructor(machine: Machine, id: string) { this.#machine = machine; this.id = id; }
  async read(options: { readonly after?: number; readonly maximum?: number } = {}): Promise<OutputPage> {
    const { after, maximum } = normalizeOutputRead(options);
    const response = await this.#machine[transport]({ kind: "read-pinned-evidence", machineId: this.#machine.id, pinId: this.id, after, maximum });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "output" || !record(response.response.page)) throw protocol("pinned output response");
    return parseEvidencePage(response.response.page);
  }
}

export type FileExpectation = { readonly kind: "any" } | { readonly kind: "absent" };
export interface FileOperationOptions extends MachineGenerationPrecondition { readonly operationId?: string; }
export class MachineFilesystem {
  readonly #machine: Machine;
  readonly #directory: Uint8Array | undefined;
  constructor(machine: Machine, directory?: Uint8Array) { this.#machine = machine; this.#directory = directory?.slice(); }
  /** A path convenience only; it neither limits filesystem authority nor normalizes Linux symlinks. */
  at(directory: string | Uint8Array): MachineFilesystem { return new MachineFilesystem(this.#machine, Uint8Array.from(this.#path(directory))); }
  #path(path: string | Uint8Array): readonly number[] {
    const bytes = typeof path === "string" ? new TextEncoder().encode(path) : path;
    if (bytes[0] === 0x2f || this.#directory === undefined) return createSandsurfGuestPath(bytes);
    const joined = new Uint8Array(this.#directory.byteLength + 1 + bytes.byteLength);
    joined.set(this.#directory); joined[this.#directory.byteLength] = 0x2f; joined.set(bytes, this.#directory.byteLength + 1);
    return createSandsurfGuestPath(joined);
  }
  stat(path: string | Uint8Array, follow = true): Promise<Record<string, unknown>> { return this.#operation({ kind: "stat", path: [...this.#path(path)], follow }); }
  lstat(path: string | Uint8Array): Promise<Record<string, unknown>> { return this.stat(path, false); }
  list(path: string | Uint8Array, options: { readonly after?: Uint8Array; readonly maximum?: number } = {}): Promise<Record<string, unknown>> { return this.#operation({ kind: "list", path: [...this.#path(path)], after: options.after === undefined ? null : [...options.after], maximum: options.maximum ?? 256 }); }
  read(path: string | Uint8Array, offset = 0, maximum = 64 * 1024): Promise<Record<string, unknown>> { return this.#operation({ kind: "read", path: [...this.#path(path)], offset, maximum }); }
  async *readStream(path: string | Uint8Array, options: MachineGenerationPrecondition & { readonly maximumBytes?: number; readonly chunkBytes?: number; readonly expectedDigest?: string } = {}): AsyncGenerator<Uint8Array> {
    const guestPath = this.#path(path);
    const authority = resolveGenerationPrecondition(this.#machine, options);
    const maximumBytes = options.maximumBytes ?? 128 * 1024 ** 3;
    const maximum = options.chunkBytes ?? 64 * 1024;
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0 || maximumBytes > 128 * 1024 ** 3
      || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 64 * 1024) throw new TypeError("file stream bounds are invalid");
    const expectedDigest = options.expectedDigest === undefined ? undefined : digest(options.expectedDigest);
    let offset = 0; let observation: { readonly size: number; readonly token: string } | undefined;
    const hash = createHash("sha256");
    for (;;) {
      const response = await this.#operation({ kind: "read", path: [...guestPath], offset, maximum }, undefined, authority);
      if (response.kind !== "read" || !record(response.range) || !record(response.range.observation)
        || (!Array.isArray(response.range.bytes) && !(response.range.bytes instanceof Uint8Array)) || integer(response.range.offset) !== offset) throw protocol("file range response");
      const observed = { size: integer(response.range.observation.size), token: digest(text(response.range.observation.token)) };
      if (observed.size > maximumBytes) throw new SandsurfHostError("capacity", "file exceeds the requested stream bound");
      if (observation !== undefined && (observed.size !== observation.size || observed.token !== observation.token)) throw new SandsurfHostError("conflict", "file changed during streamed read");
      observation = observed;
      const bytes = response.range.bytes instanceof Uint8Array ? response.range.bytes : Uint8Array.from(response.range.bytes as number[]);
      if (bytes.byteLength > maximum || offset + bytes.byteLength > maximumBytes) throw protocol("file range exceeds its credit");
      hash.update(bytes); offset += bytes.byteLength;
      if (bytes.byteLength !== 0) yield bytes;
      if (response.range.eof === true) break;
      if (bytes.byteLength === 0) throw protocol("empty non-terminal file range");
    }
    const actualDigest = hash.digest("hex");
    if (observation === undefined || observation.size !== offset) throw protocol("file stream did not capture its reported size");
    if (expectedDigest !== undefined && actualDigest !== expectedDigest) throw new SandsurfHostError("integrity", "captured file bytes do not match the caller's expected digest");
  }
  async readFile(path: string | Uint8Array, options: MachineGenerationPrecondition & { readonly maximumBytes?: number; readonly expectedDigest?: string } = {}): Promise<Uint8Array> {
    const chunks: Uint8Array[] = []; let length = 0;
    for await (const chunk of this.readStream(path, { ...options, maximumBytes: options.maximumBytes ?? 64 * 1024 ** 2 })) { chunks.push(chunk); length += chunk.byteLength; }
    const result = new Uint8Array(length); let cursor = 0;
    for (const chunk of chunks) { result.set(chunk, cursor); cursor += chunk.byteLength; }
    return result;
  }
  async writeFile(path: string | Uint8Array, bytes: string | Uint8Array, options: FileOperationOptions & { readonly mode?: number; readonly expected?: FileExpectation; readonly transferId?: string } = {}): Promise<Record<string, unknown>> {
    const value = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
    return this.writeStream(path, [value], { length: value.byteLength, digest: createHash("sha256").update(value).digest("hex"), ...options });
  }
  async writeStream(path: string | Uint8Array, chunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>, options: FileOperationOptions & { readonly length: number; readonly digest: string; readonly mode?: number; readonly expected?: FileExpectation; readonly transferId?: string }): Promise<Record<string, unknown>> {
    if (!Number.isSafeInteger(options.length) || options.length < 0 || options.length > 128 * 1024 ** 3) throw new TypeError("stream length is invalid");
    const operationId = validateIdentity(options.operationId ?? identity("write-file"));
    const transfer = { id: validateIdentity(options.transferId ?? childIdentity(operationId, "transfer")), path: [...this.#path(path)], length: options.length, digest: digest(options.digest), mode: options.mode ?? 0o644, expected: options.expected ?? { kind: "any" } };
    let remoteOperationStarted = false;
    const perform = async (request: Readonly<Record<string, unknown>>, child: string): Promise<Record<string, unknown>> => {
      remoteOperationStarted = true;
      return this.#operation(request, childIdentity(operationId, child), options);
    };
    await perform({ kind: "begin-write", transfer }, "begin");
    remoteOperationStarted = false;
    try {
      let offset = 0; let buffered = new Uint8Array(64 * 1024); let bufferedBytes = 0;
      const flush = async (): Promise<void> => {
        if (bufferedBytes === 0) return;
        const bytes = buffered.slice(0, bufferedBytes);
        await perform({ kind: "write-chunk", transfer, offset, bytes: [...bytes] }, `chunk-${offset}`);
        remoteOperationStarted = false; offset += bytes.byteLength; buffered = new Uint8Array(64 * 1024); bufferedBytes = 0;
      };
      for await (const supplied of chunks) {
        if (!(supplied instanceof Uint8Array)) throw new TypeError("stream chunks must be Uint8Array values");
        let cursor = 0;
        while (cursor < supplied.byteLength) { const take = Math.min(buffered.byteLength - bufferedBytes, supplied.byteLength - cursor); buffered.set(supplied.subarray(cursor, cursor + take), bufferedBytes); bufferedBytes += take; cursor += take; if (bufferedBytes === buffered.byteLength) await flush(); }
      }
      await flush();
      if (offset !== options.length) throw new SandsurfHostError("transfer", "stream byte count does not match its declaration");
      return await perform({ kind: "commit-write", transfer }, "commit");
    } catch (error) {
      // Once a remote operation has begun, delivery may be ambiguous. Keep the
      // staged transfer so the caller can reconcile/retry the stable child IDs.
      if (!remoteOperationStarted) { try { await this.#operation({ kind: "abort-write", transfer }, childIdentity(operationId, "abort"), options); } catch { /* Preserve the original failure. */ } }
      throw error;
    }
  }
  async mkdir(path: string | Uint8Array, options: FileOperationOptions & { readonly recursive?: boolean } = {}): Promise<void> { await this.#operation({ kind: "mkdir", path: [...this.#path(path)], recursive: options.recursive ?? false }, validateIdentity(options.operationId ?? identity("mkdir")), options); }
  async rename(from: string | Uint8Array, to: string | Uint8Array, options: FileOperationOptions = {}): Promise<void> { await this.#operation({ kind: "rename", from: [...this.#path(from)], to: [...this.#path(to)] }, validateIdentity(options.operationId ?? identity("rename")), options); }
  async remove(path: string | Uint8Array, options: FileOperationOptions & { readonly recursive?: boolean } = {}): Promise<void> { await this.#operation({ kind: "remove", path: [...this.#path(path)], recursive: options.recursive ?? false }, validateIdentity(options.operationId ?? identity("remove")), options); }
  async chmod(path: string | Uint8Array, mode: number, options: FileOperationOptions = {}): Promise<void> { await this.#operation({ kind: "chmod", path: [...this.#path(path)], mode }, validateIdentity(options.operationId ?? identity("chmod")), options); }
  async readlink(path: string | Uint8Array): Promise<Uint8Array> { const response = await this.#operation({ kind: "readlink", path: [...this.#path(path)] }); if (response.kind !== "link" || !Array.isArray(response.target)) throw protocol("readlink response"); return Uint8Array.from(response.target as number[]); }
  async symlink(path: string | Uint8Array, target: Uint8Array, options: FileOperationOptions = {}): Promise<void> { await this.#operation({ kind: "symlink", path: [...this.#path(path)], target: [...target] }, validateIdentity(options.operationId ?? identity("symlink")), options); }
  async watch(path: string | Uint8Array, options: FileOperationOptions & { readonly recursive?: boolean; readonly watcherId?: string } = {}): Promise<FilesystemWatcher> {
    const authority = resolveGenerationPrecondition(this.#machine, options); const watcherId = validateIdentity(options.watcherId ?? identity("watcher"));
    await this.#operation({ kind: "watch", watcherId, generation: authority.expectedGeneration, path: [...this.#path(path)], recursive: options.recursive ?? false }, validateIdentity(options.operationId ?? identity("watch")), authority);
    return new FilesystemWatcher(this, watcherId, authority.expectedGeneration);
  }
  async pollWatcher(watcherId: string, generation: number, maximum = 256): Promise<readonly Readonly<Record<string, unknown>>[]> { const response = await this.#operation({ kind: "poll-watch", watcherId, generation, maximum }); if (response.kind !== "watch" || !Array.isArray(response.events)) throw protocol("watch response"); return response.events.map((event) => { if (!record(event)) throw protocol("watch event"); return event; }); }
  async closeWatcher(watcherId: string, generation: number, options: FileOperationOptions = {}): Promise<void> { await this.#operation({ kind: "unwatch", watcherId, generation }, validateIdentity(options.operationId ?? identity("unwatch")), options); }
  async #operation(request: Readonly<Record<string, unknown>>, operationId = identity("file"), precondition: MachineGenerationPrecondition = {}): Promise<Record<string, unknown>> {
    if (typeof request.kind === "string" && ["stat", "list", "read", "readlink", "poll-watch"].includes(request.kind)) {
      const response = await this.#machine[queryGuest]({ kind: "filesystem-query", request }, precondition);
      if (response.kind !== "file" || !record(response.response)) throw protocol("filesystem response"); return response.response;
    }
    const operation = await this.#machine[dispatchGuest]({ kind: "filesystem", request }, operationId, precondition); const admission = operation.admission;
    const command = record(admission) ? admission.request : undefined;
    if (!record(command)) throw protocol("filesystem operation receipt");
    const response = await this.#machine[queryGuest]({ kind: "operation", operationId, requestDigest: text(command.requestDigest) });
    if (response.kind !== "file" || !record(response.response)) throw protocol("filesystem response"); return response.response;
  }
}

export class FilesystemWatcher {
  readonly id: string; readonly generation: number; readonly #filesystem: MachineFilesystem; #closed = false;
  constructor(filesystem: MachineFilesystem, id: string, generation: number) { this.#filesystem = filesystem; this.id = id; this.generation = generation; }
  poll(maximum = 256): Promise<readonly Readonly<Record<string, unknown>>[]> { if (this.#closed) throw new SandsurfHostError("client", "Filesystem watcher is closed"); return this.#filesystem.pollWatcher(this.id, this.generation, maximum); }
  async close(options: FileOperationOptions = {}): Promise<void> { if (!this.#closed) { await this.#filesystem.closeWatcher(this.id, this.generation, options); this.#closed = true; } }
}

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

export class ArtifactCollection {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async get(machineId: string, id: string): Promise<Artifact> {
    validateIdentity(machineId); validateIdentity(id);
    const entries: TreeEntry[] = [];
    let inspection: ArtifactInspection | undefined; let after = 0;
    for (;;) {
      const page = await this.#host[transport]({ kind: "list-host-tree", machineId, operationId: id, after, maximum: 128 });
      if (page.kind !== "host-tree-entries" || !record(page.capture) || !Array.isArray(page.entries)) throw protocol("artifact entries");
      const observed = parseHostCapture(page.capture);
      if (observed.id !== id || observed.machineId !== machineId
        || (inspection !== undefined && (observed.manifestDigest !== inspection.manifestDigest || observed.requestDigest !== inspection.requestDigest))) throw protocol("artifact identity");
      inspection = observed;
      for (const entry of page.entries) entries.push(parseTreeEntry(entry));
      if (page.next === null) break;
      const next = integer(page.next);
      if (next <= after || page.entries.length === 0) throw protocol("artifact pagination");
      after = next;
    }
    const manifest = treeManifest(entries, id);
    if (inspection === undefined || entries.length !== inspection.entries || manifest.digest !== inspection.manifestDigest) throw protocol("artifact manifest coverage");
    return new Artifact(this.#host, inspection, manifest);
  }
}

export class MachineArtifacts {
  readonly #machine: Machine; readonly #host: Sandsurf;
  constructor(machine: Machine, host: Sandsurf) { this.#machine = machine; this.#host = host; }
  async capture(source: string | Uint8Array, options: ArtifactCaptureOptions = {}): Promise<Artifact> {
    const path = [...createSandsurfGuestPath(source)];
    const operationId = validateIdentity(options.operationId ?? identity("artifact"));
    const view = await this.#machine.inspect();
    const expectedRevision = expectedCounter(options.expectedRevision, "expected revision") ?? view.configurationRevision;
    const expectedGeneration = expectedCounter(options.expectedGeneration, "expected generation") ?? currentMachine(view).generation;
    const maximumBytes = options.maximumBytes ?? Math.min(view.resources.diskBytes, 128 * 1024 ** 3);
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0 || maximumBytes > 128 * 1024 ** 3) throw new TypeError("artifact capture bound is invalid");
    const response = await this.#machine[transport]({ kind: "capture-guest-tree", machineId: this.#machine.id, source: path, operationId, expectedRevision, expectedGeneration, maximumBytes });
    if (response.kind !== "host-tree-capture" || !record(response.capture)) throw protocol("artifact capture");
    const capture = parseHostCapture(response.capture);
    if (capture.id !== operationId || capture.machineId !== this.#machine.id) throw protocol("artifact capture identity");
    return this.#host.artifacts.get(this.#machine.id, operationId);
  }
  async importFromHost(options: ArtifactImportOptions): Promise<Artifact> {
    if (!isAbsolute(options.source)) throw new TypeError("host import source must be absolute");
    const source = resolve(options.source);
    const operationId = validateIdentity(options.operationId ?? identity("import"));
    const exclusions = [...normalizeExclusions(options.exclusions ?? [])].sort();
    const maximumBytes = options.maximumBytes ?? 8 * 1024 ** 3;
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0 || maximumBytes > 128 * 1024 ** 3) throw new TypeError("host import bound is invalid");
    const authority = await resolveMachinePreconditions(this.#machine, options);
    const approvalId = await this.#machine[authorize]({ kind: "host-import", machineId: this.#machine.id, operationId, request: { source, exclusions, maximumBytes, expectedRevision: authority.expectedRevision } });
    const response = await this.#machine[transport]({ kind: "capture-host-tree", machineId: this.#machine.id, operationId, expectedRevision: authority.expectedRevision, source, exclusions, maximumBytes, approvalId });
    if (response.kind !== "host-tree-capture" || !record(response.capture)) throw protocol("host artifact capture");
    const artifact = await this.#host.artifacts.get(this.#machine.id, operationId);
    await artifact.writeTo(this.#machine, options.destination, { operationId, expectedGeneration: authority.expectedGeneration });
    return artifact;
  }
}

export class Artifact {
  readonly id: string; readonly inspection: ArtifactInspection; readonly manifest: TreeManifest;
  readonly #host: Sandsurf;
  constructor(host: Sandsurf, inspection: ArtifactInspection, manifest: TreeManifest) {
    validateTreeManifest(manifest);
    this.#host = host; this.id = inspection.id; this.inspection = Object.freeze({ ...inspection });
    this.manifest = Object.freeze({ ...manifest, entries: Object.freeze(manifest.entries.map((entry) => Object.freeze({ ...entry, target: entry.target === null ? null : Object.freeze([...entry.target]) }))) });
  }
  compare(base?: Artifact): ChangeSet {
    const previous = base?.manifest ?? treeManifest([]);
    const old = new Map(previous.entries.map((entry) => [entry.path, entry]));
    const next = new Map(this.manifest.entries.map((entry) => [entry.path, entry]));
    const changes: TreeChange[] = [...old.keys()].filter((path) => !next.has(path))
      .sort((left, right) => pathDepth(right) - pathDepth(left) || Buffer.from(left).compare(Buffer.from(right)))
      .map((path) => ({ kind: "delete", path }));
    const upserts = this.manifest.entries.filter((entry) => { const prior = old.get(entry.path); return prior === undefined || treeEntryDigest(prior) !== treeEntryDigest(entry); });
    upserts.sort((left, right) => (left.kind === "directory" ? 0 : 1) - (right.kind === "directory" ? 0 : 1) || pathDepth(left.path) - pathDepth(right.path) || Buffer.from(left.path).compare(Buffer.from(right.path)));
    for (const entry of upserts) changes.push({ kind: "upsert", entry });
    return treeChangeSet(previous, changes, this.id);
  }
  async writeTo(machine: Machine, destination: string | Uint8Array, options: ExecutionOperationOptions = {}): Promise<void> {
    const filesystem = machine.fs.at(destination);
    const authority = resolveGenerationPrecondition(machine, options);
    const operationId = validateIdentity(options.operationId ?? identity("materialize-artifact"));
    await machine.fs.mkdir(destination, { recursive: true, operationId: childIdentity(operationId, "root"), ...authority });
    for (const entry of this.manifest.entries) if (entry.kind === "directory") await filesystem.mkdir(entry.path, { recursive: true, operationId: childIdentity(operationId, `mkdir-${entry.path}`), ...authority });
    for (const entry of this.manifest.entries) {
      if (entry.kind === "directory") continue;
      if (entry.kind === "symlink") {
        if (entry.target === null) throw protocol("artifact link target");
        await filesystem.symlink(entry.path, Uint8Array.from(entry.target), { operationId: childIdentity(operationId, `symlink-${entry.path}`), ...authority });
      } else {
        if (entry.digest === null) throw protocol("artifact file digest");
        await filesystem.writeStream(entry.path, this.#blob(entry.digest, entry.size), { length: entry.size, digest: entry.digest, mode: entry.mode, expected: { kind: "absent" }, operationId: childIdentity(operationId, `write-${entry.path}`), ...authority });
      }
    }
    for (const entry of [...this.manifest.entries].reverse()) if (entry.kind === "directory") await filesystem.chmod(entry.path, entry.mode, { operationId: childIdentity(operationId, `chmod-${entry.path}`), ...authority });
  }
  async applyToHost(options: ArtifactApplyOptions): Promise<HostApplyReport> {
    if (!isAbsolute(options.destination)) throw new TypeError("host apply destination must be absolute");
    const destination = resolve(options.destination); const operationId = validateIdentity(options.operationId ?? identity("apply"));
    const changeSet = this.compare(options.base);
    const machineId = this.inspection.machineId;
    const approvalId = await this.#host[authorize]({
      kind: "host-apply", machineId, operationId,
      request: { artifactId: this.id, manifestDigest: this.manifest.digest, destination, changeSetDigest: changeSet.digest },
    });
    const { captureOperationId: _captureOperationId, ...supplied } = changeSet;
    const response = await this.#host[transport]({ kind: "apply-artifact-to-host", machineId, artifactId: this.id, operationId, destination, changeSet: supplied, approvalId });
    if (response.kind !== "host-apply" || !record(response.report)) throw protocol("artifact host application");
    return { operationId: text(response.report.operationId), changeSetDigest: digest(text(response.report.changeSetDigest)), applied: integer(response.report.applied), recovered: response.report.recovered === true };
  }
  async *readStream(path: string): AsyncGenerator<Uint8Array> {
    validatePortableTreePath(path);
    const entry = this.manifest.entries.find((value) => value.path === path);
    if (entry?.kind !== "file" || entry.digest === null) throw new SandsurfHostError("missing", "artifact has no regular file at that path");
    yield* this.#blob(entry.digest, entry.size);
  }
  async readFile(path: string, options: { readonly maximumBytes?: number } = {}): Promise<Uint8Array> {
    const maximum = options.maximumBytes ?? 64 * 1024 ** 2;
    if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > 64 * 1024 ** 2) throw new TypeError("artifact in-memory read bound is invalid");
    const entry = this.manifest.entries.find((value) => value.path === path);
    if (entry === undefined || entry.size > maximum) throw new SandsurfHostError("capacity", "artifact file exceeds the read bound");
    const chunks: Uint8Array[] = []; let length = 0;
    for await (const chunk of this.readStream(path)) { chunks.push(chunk); length += chunk.byteLength; if (length > maximum) throw protocol("artifact read credit"); }
    return Buffer.concat(chunks, length);
  }
  async *#blob(expectedDigest: string, expectedLength: number): AsyncGenerator<Uint8Array> {
    let offset = 0; const hash = createHash("sha256");
    for (;;) {
      const response = await this.#host[transport]({ kind: "read-host-tree-blob", machineId: this.inspection.machineId, operationId: this.id, digest: expectedDigest, offset, maximum: 64 * 1024 });
      if (response.kind !== "host-blob" || response.digest !== expectedDigest || integer(response.offset) !== offset || (!Array.isArray(response.bytes) && !(response.bytes instanceof Uint8Array)) || typeof response.eof !== "boolean") throw protocol("artifact blob");
      const bytes = response.bytes instanceof Uint8Array ? response.bytes : Uint8Array.from(response.bytes as number[]);
      if (bytes.byteLength > 64 * 1024 || offset + bytes.byteLength > expectedLength || (bytes.byteLength === 0 && !response.eof)) throw protocol("artifact blob credit");
      hash.update(bytes); offset += bytes.byteLength;
      if (bytes.byteLength !== 0) yield bytes;
      if (response.eof) break;
    }
    if (offset !== expectedLength || hash.digest("hex") !== expectedDigest) throw new SandsurfHostError("integrity", "artifact bytes do not match their immutable digest");
  }
}

export interface TreeEntry { readonly path: string; readonly kind: "directory" | "file" | "symlink"; readonly mode: number; readonly size: number; readonly digest: string | null; readonly target: readonly number[] | null; }
export interface TreeManifest { readonly digest: string; readonly entries: readonly TreeEntry[]; readonly captureOperationId?: string; }
export type TreeChange = { readonly kind: "upsert"; readonly entry: TreeEntry } | { readonly kind: "delete"; readonly path: string };
export interface ChangeSet { readonly baseManifestDigest: string; readonly base: readonly TreeEntry[]; readonly changes: readonly TreeChange[]; readonly digest: string; readonly captureOperationId: string; }
export interface HostApplyReport { readonly operationId: string; readonly changeSetDigest: string; readonly applied: number; readonly recovered: boolean; }

function normalizeResources(value: ResourceEnvelope): Required<ResourceEnvelope> {
  const outputBytes = value.outputBytes ?? 1024 * 1024 * 1024; const managedExecutions = value.managedExecutions ?? 1024;
  for (const item of [value.vcpus, value.memoryMiB, value.diskBytes, outputBytes, managedExecutions]) if (!Number.isSafeInteger(item) || item <= 0) throw new TypeError("resource values must be positive safe integers");
  return { vcpus: value.vcpus, memoryMiB: value.memoryMiB, diskBytes: value.diskBytes, outputBytes, managedExecutions };
}
function normalizeExecutionDefaults(options: MachineCreateOptions): Readonly<Record<string, unknown>> {
  const environment = { ...(options.environment ?? {}) };
  const entries = Object.entries(environment);
  if (entries.length > 4096 || entries.some(([name, value]) => name.length < 1 || name.length > 512 || name.includes("\0") || name.includes("=") || typeof value !== "string" || value.length > 64 * 1024 || value.includes("\0"))) throw new TypeError("Machine environment is malformed");
  const user = options.user ?? null;
  if (user !== null && (typeof user !== "string" || user.length < 1 || user.length > 256 || user.includes("\0"))) throw new TypeError("Machine user is malformed");
  const workingDirectory = options.workingDirectory ?? null;
  if (workingDirectory !== null) createSandsurfGuestPath(workingDirectory);
  return { environment, user, workingDirectory };
}
function normalizeLifetime(value: MachineLifetimePolicy | undefined): Readonly<{ expiresAtUnixMillis: number | null; expirationAction: "stop" | "destroy" }> {
  const expiresAtUnixMillis = value?.expiresAtUnixMs ?? null;
  const expirationAction = value?.expirationAction ?? "stop";
  if (expiresAtUnixMillis !== null && (!Number.isSafeInteger(expiresAtUnixMillis) || expiresAtUnixMillis <= 0)) throw new TypeError("absolute Machine expiration must be a positive Unix millisecond value");
  if (expirationAction !== "stop" && expirationAction !== "destroy") throw new TypeError("Machine expiration action is invalid");
  return { expiresAtUnixMillis, expirationAction };
}
function machineViewFrom(response: Record<string, unknown>): MachineInspection { if (response.kind === "lifecycle") { if (!record(response.operation) || typeof response.operation.delivery !== "string") throw protocol("lifecycle operation"); if (response.operation.delivery !== "applied") throw new SandsurfHostError(response.operation.delivery === "not-applied" ? "not-applied" : "ambiguous", `Lifecycle operation was ${response.operation.delivery}`); } const value = response.kind === "machine" ? response.value : response.kind === "lifecycle" ? response.machine : undefined; if (!record(value)) throw protocol("machine response"); return parseView(value); }
function parseView(value: unknown): MachineInspection { if (!record(value) || !record(value.resources) || !record(value.runtimeConfiguration) || !record(value.lifecycleIntent) || !record(value.machine) || !record(value.executionDefaults) || !record(value.lifetime)) throw protocol("machine view"); const expirationAction = text(value.lifetime.expirationAction); if (expirationAction !== "stop" && expirationAction !== "destroy") throw protocol("Machine lifetime policy"); const lifetime = { expiresAtUnixMillis: value.lifetime.expiresAtUnixMillis === null ? null : integer(value.lifetime.expiresAtUnixMillis), expirationAction }; return { ...value, lifetime, lastActivityUnixMillis: integer(value.lastActivityUnixMillis), runtimeConfiguration: parseRuntimeConfiguration(value.runtimeConfiguration) } as unknown as MachineInspection; }
function currentMachine(view: MachineInspection): { readonly generation: number } { if (view.machine.kind !== "current" || !record(view.machine.value)) throw new SandsurfHostError("unavailable", "Machine machine observation is unavailable"); return { generation: integer(view.machine.value.generation) }; }
function nativeObservationOrder(observation: Readonly<Record<string, unknown>>): readonly [number, number] {
  const value = observation.kind === "current" ? observation.value : observation.lastKnown;
  if (!record(value)) return [0, 0];
  return [integer(value.generation), integer(value.sequence)];
}
function expectedCounter(value: number | undefined, name: string): number | undefined { if (value === undefined) return undefined; if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${name} must be a positive safe integer`); return value; }
async function resolveRevisionPrecondition(machine: Machine, supplied: number | undefined): Promise<number> { const expected = expectedCounter(supplied, "expected revision"); return expected ?? machine[observed].configurationRevision; }
function resolveGenerationPrecondition(machine: Machine, supplied: MachineGenerationPrecondition): { readonly expectedGeneration: number } {
  const generation = expectedCounter(supplied.expectedGeneration, "expected generation");
  return { expectedGeneration: generation ?? currentMachine(machine[observed]).generation };
}
function resolveMachinePreconditions(machine: Machine, supplied: MachineGenerationPrecondition & MachineRevisionPrecondition): { readonly expectedRevision: number; readonly expectedGeneration: number } {
  return { ...resolveGenerationPrecondition(machine, supplied), expectedRevision: expectedCounter(supplied.expectedRevision, "expected revision") ?? machine[observed].configurationRevision };
}
function parseProcess(value: unknown): ExecutionInspection { if (!record(value) || !record(value.request) || !record(value.state) || (value.lineage !== null && !record(value.lineage))) throw protocol("process inspection"); return { request: value.request, guestPid: integer(value.guestPid), state: value.state, lineage: value.lineage }; }
function parseExecutionObservation(value: unknown): ExecutionObservation { if (!record(value) || (value.kind !== "current" && value.kind !== "unavailable")) throw protocol("process observation"); if (value.kind === "current") return { kind: "current", value: parseProcess(value.value) }; return { kind: "unavailable", lastKnown: value.lastKnown === null ? null : parseProcess(value.lastKnown) }; }
function runtimeEventBelongsToProcess(event: MachineEvent, executionId: string): boolean {
  const value = event.value;
  if ((value.kind === "output" || value.kind === "receipt" || value.kind === "evidence-release") && value.executionId === executionId) return true;
  return value.kind === "process" && record(value.process) && record(value.process.request) && value.process.request.executionId === executionId;
}
function parseEvidencePage(value: Record<string, unknown>): OutputPage {
  if (!Array.isArray(value.chunks)) throw protocol("output page");
  const after = integer(value.after); const cursor = integer(value.cursor); const available = integer(value.available);
  if (cursor < after || available < cursor) throw protocol("output page cursors");
  let expected = after;
  const chunks = value.chunks.map((chunk: unknown) => {
    if (!record(chunk) || (!Array.isArray(chunk.bytes) && !(chunk.bytes instanceof Uint8Array))) throw protocol("output chunk");
    const offset = integer(chunk.offset); const stream = text(chunk.stream); const expectedDigest = digest(text(chunk.bytesDigest));
    const bytes = chunk.bytes instanceof Uint8Array ? chunk.bytes : Uint8Array.from(chunk.bytes as number[]);
    if (offset !== expected || bytes.byteLength === 0 || bytes.byteLength > 64 * 1024 ||
        !["stdout", "stderr", "terminal"].includes(stream) ||
        createHash("sha256").update(bytes).digest("hex") !== expectedDigest) throw protocol("output chunk coverage or digest");
    expected += bytes.byteLength;
    return { cursor: offset, stream: stream as OutputChunk["stream"], bytes, digest: expectedDigest };
  });
  if (expected !== cursor) throw protocol("output page coverage");
  return { after, available, chunks };
}
function normalizeOutputRead(options: { readonly after?: number; readonly maximum?: number }): { readonly after: number; readonly maximum: number } { const after = options.after ?? 0; const maximum = options.maximum ?? 64 * 1024; if (!Number.isSafeInteger(after) || after < 0) throw new TypeError("output cursor must be a nonnegative safe integer"); if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 256 * 1024) throw new TypeError("output page size must be 1 through 256 KiB"); return { after, maximum }; }
function normalizeNetworkPolicy(value: NetworkPolicy): NetworkPolicy {
  if (!Array.isArray(value.rules) || value.rules.length > 4096) throw new TypeError("network policy exceeds its rule bound");
  const rules = value.rules.map((rule: NetworkRule) => {
    if (!(["named-proxy", "direct-tcp", "dns"] as const).includes(rule.plane) || !Array.isArray(rule.ports) || rule.ports.length === 0 || rule.ports.length > 4096) throw new TypeError("network rule is malformed");
    const ports = rule.ports.map((port: number | { readonly from: number; readonly to: number }) => { const range = typeof port === "number" ? { from: port, to: port } : port; if (!Number.isInteger(range.from) || !Number.isInteger(range.to) || range.from < 1 || range.from > range.to || range.to > 65535) throw new TypeError("network port range is malformed"); return range; });
    let destination: NetworkDestination;
    if (rule.destination.kind === "dns") { const name = rule.destination.name.toLowerCase().replace(/\.$/u, ""); if (name.length === 0 || name.length > 253 || name.includes("*") || name.split(".").some((label: string) => label.length === 0 || label.length > 63)) throw new TypeError("network DNS name is malformed"); if (rule.plane === "direct-tcp") throw new TypeError("direct TCP rules require an IP CIDR"); destination = { kind: "dns", name, includeSubdomains: rule.destination.includeSubdomains ?? false, allowPrivateAddresses: rule.destination.allowPrivateAddresses ?? false }; }
    else { const [address, prefixText, extra] = rule.destination.cidr.split("/"); const family = address === undefined ? 0 : isIP(address); const prefix = Number(prefixText); if (extra !== undefined || family === 0 || !Number.isInteger(prefix) || prefix < 0 || prefix > (family === 4 ? 32 : 128) || rule.plane !== "direct-tcp") throw new TypeError("direct TCP CIDR is malformed"); destination = { kind: "ip", cidr: `${address}/${prefix}` }; }
    return { plane: rule.plane, destination, ports };
  });
  return { rules };
}
function normalizeExposure(value: ExposureSpec): Exposure["spec"] { const guestAddress = value.guestAddress ?? "127.0.0.1"; const hostAddress = value.hostAddress ?? "127.0.0.1"; const guestPort = value.guestPort; const hostPort = value.hostPort ?? 0; const publicValue = value.public ?? false; if (isIP(guestAddress) === 0 || !["127.0.0.1", "::1"].includes(guestAddress) || isIP(hostAddress) === 0 || (!publicValue && !["127.0.0.1", "::1"].includes(hostAddress)) || !Number.isInteger(guestPort) || guestPort < 1 || guestPort > 65535 || !Number.isInteger(hostPort) || hostPort < 0 || hostPort > 65535) throw new TypeError("port exposure is malformed"); return { guestAddress, guestPort, hostAddress, hostPort, public: publicValue }; }
function parseRuntimeConfiguration(value: Record<string, unknown>): RuntimeConfiguration { if (!record(value.network) || !Array.isArray(value.network.rules) || !Array.isArray(value.exposures) || !record(value.resources)) throw protocol("runtime configuration"); return { network: normalizeNetworkPolicy(value.network as unknown as NetworkPolicy), exposures: value.exposures.map(parseExposure), resources: normalizeResources(value.resources as unknown as ResourceEnvelope) }; }
function parseExposure(value: unknown): Exposure { if (!record(value) || !record(value.spec)) throw protocol("exposure"); return { id: validateIdentity(text(value.id)), machineId: validateIdentity(text(value.machineId)), revision: integer(value.revision), spec: normalizeExposure({ guestAddress: text(value.spec.guestAddress), guestPort: integer(value.spec.guestPort), hostAddress: text(value.spec.hostAddress), hostPort: integer(value.spec.hostPort), public: value.spec.public === true }), active: value.active === true, boundPort: value.boundPort === null ? null : integer(value.boundPort) }; }
function parseSecret(value: Record<string, unknown>): SecretVersion { return { id: validateIdentity(text(value.id)), version: validateIdentity(text(value.version)), bytes: integer(value.bytes) }; }
function parseSecretRevocation(value: Record<string, unknown>): SecretRevocation {
  const evidence = value.guestCleanupReport;
  if (!record(value.secret) || (evidence !== null && !record(evidence))) throw protocol("secret revocation evidence");
  const parsedEvidence = evidence === null ? null : {
    filesRemoved: integer(evidence.filesRemoved),
    environmentBindingsRemoved: integer(evidence.environmentBindingsRemoved),
    recipientsTerminated: identityList(evidence.recipientsTerminated),
    recipientsAlreadyStopped: identityList(evidence.recipientsAlreadyStopped),
    residualCopiesPossible: evidence.residualCopiesPossible === true,
    actionsReportedComplete: evidence.actionsReportedComplete === true,
  };
  return { operationId: validateIdentity(text(value.operationId)), machineId: validateIdentity(text(value.machineId)), secret: parseSecret(value.secret), terminateRecipients: value.terminateRecipients === true, futureDeliveryRevoked: true, guestCleanupReport: parsedEvidence };
}
function identityList(value: unknown): readonly string[] { if (!Array.isArray(value) || value.length > 1024) throw protocol("identity list"); return value.map((item) => validateIdentity(text(item))); }
function parseUsage(value: Record<string, unknown>): ResourceUsage { return { cpuMicros: value.cpuMicros === null ? null : integer(value.cpuMicros), memoryCurrent: value.memoryCurrent === null ? null : integer(value.memoryCurrent), memoryPeak: value.memoryPeak === null ? null : integer(value.memoryPeak), diskLogicalBytes: integer(value.diskLogicalBytes), diskAllocatedBytes: integer(value.diskAllocatedBytes), ioReadBytes: value.ioReadBytes === null ? null : integer(value.ioReadBytes), ioWriteBytes: value.ioWriteBytes === null ? null : integer(value.ioWriteBytes), outputRetainedBytes: integer(value.outputRetainedBytes), networkRxBytes: integer(value.networkRxBytes), networkTxBytes: integer(value.networkTxBytes), networkConnections: integer(value.networkConnections), executionsCurrent: integer(value.executionsCurrent), complete: value.complete === true, source: text(value.source), observedUnixMillis: integer(value.observedUnixMillis) }; }
function normalizeOciSource(options: ImageImportOptions): Readonly<Record<string, unknown>> {
  if (options.source !== undefined && options.reference !== undefined) throw new TypeError("Specify either source or reference for OCI import");
  const source = options.source ?? (options.reference === undefined ? undefined : { kind: "registry" as const, reference: options.reference });
  if (source === undefined) throw new TypeError("OCI import requires a source or registry reference");
  if (source.kind === "layout" || source.kind === "archive") {
    if (!isAbsolute(source.path)) throw new TypeError("OCI host paths must be absolute");
    return { kind: source.kind, path: resolve(source.path) };
  }
  if (source.reference.length === 0 || source.reference.length > 4096) throw new TypeError("OCI registry reference is malformed");
  const credential = source.credential === undefined ? null : parseSecret(source.credential as unknown as Record<string, unknown>);
  return { kind: "registry", reference: source.reference, credential };
}
function parseImage(value: unknown): ImageInspection {
  if (!record(value)) throw protocol("image record");
  return { digest: digest(text(value.digest)), sourceDigest: digest(text(value.sourceDigest)), platform: text(value.platform), architecture: text(value.architecture), logicalBytes: integer(value.logicalBytes), storageBytes: integer(value.storageBytes), provenanceDigest: digest(text(value.provenanceDigest)), sensitive: value.sensitive === true };
}
function parseSnapshot(value: unknown): SnapshotInspection {
  if (!record(value) || !record(value.request) || !record(value.resources)) throw protocol("snapshot record");
  const consistency = value.consistency === null ? null : text(value.consistency) as SnapshotConsistency;
  if (consistency !== null && !["crash", "machine"].includes(consistency)) throw protocol("snapshot consistency");
  const kind = text(value.request.kind) as SnapshotKind; if (kind !== "disk" && kind !== "full") throw protocol("snapshot kind");
  const phase = text(value.phase) as SnapshotInspection["phase"]; if (!["admitted", "capturing", "ready"].includes(phase)) throw protocol("snapshot phase");
  return { id: validateIdentity(text(value.request.id)), operationId: validateIdentity(text(value.request.operationId)), machineId: validateIdentity(text(value.request.machineId)), expectedGeneration: integer(value.request.expectedGeneration), expectedRevision: integer(value.request.expectedRevision), kind, parent: value.request.parent === null ? null : validateIdentity(text(value.request.parent)), requestDigest: digest(text(value.requestDigest)), phase, imageDigest: digest(text(value.imageDigest)), resources: normalizeResources(value.resources as unknown as ResourceEnvelope), consistency, systemDiskDigest: value.systemDiskDigest === null ? null : digest(text(value.systemDiskDigest)), systemDiskBytes: integer(value.systemDiskBytes), manifestDigest: value.manifestDigest === null ? null : digest(text(value.manifestDigest)), sensitive: value.sensitive === true };
}
function parseReleaseStatus(value: Record<string, unknown>): ReleaseStatus { return { requestDigest: digest(text(value.requestDigest)), cleanupPending: value.cleanupPending === true }; }
function normalizeExclusions(values: readonly string[]): ReadonlySet<string> {
  const result = new Set<string>();
  for (const value of values) {
    validatePortableTreePath(value);
    result.add(value);
  }
  return result;
}
function treeManifest(entries: readonly TreeEntry[], captureOperationId?: string): TreeManifest {
  const ordered = [...entries].sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  const paths = new Set<string>(); for (const entry of ordered) { validateTreeEntry(entry); if (paths.has(entry.path)) throw new TypeError("artifact manifest paths must be unique"); paths.add(entry.path); }
  const hash = createHash("sha256").update("SANDSURF-TREE-MANIFEST-V1\0");
  for (const entry of ordered) hash.update(Buffer.from(treeEntryDigest(entry), "hex"));
  return { digest: hash.digest("hex"), entries: ordered, ...(captureOperationId === undefined ? {} : { captureOperationId: validateIdentity(captureOperationId) }) };
}
function treeEntryDigest(entry: TreeEntry): string { return sandsurfDigest("transfer", ["sandsurf-tree-entry-v1", entry]); }
function treeChangeSet(base: TreeManifest, changes: readonly TreeChange[], captureOperationId: string): ChangeSet {
  const hash = createHash("sha256").update("SANDSURF-TREE-CHANGES-V1\0");
  const paths = new Set<string>();
  for (const change of changes) { const path = change.kind === "upsert" ? change.entry.path : change.path; validatePortableTreePath(path); if (change.kind === "upsert") validateTreeEntry(change.entry); if (paths.has(path)) throw new TypeError("artifact change paths must be unique"); paths.add(path); hash.update(Buffer.from(sandsurfDigest("transfer", ["sandsurf-tree-change-v1", change]), "hex")); }
  const changesDigest = hash.digest("hex"); return { baseManifestDigest: base.digest, base: base.entries, changes: [...changes], digest: sandsurfDigest("transfer", ["sandsurf-tree-change-set-v1", base.digest, changesDigest]), captureOperationId: validateIdentity(captureOperationId) };
}
function validateTreeManifest(value: TreeManifest): void { const rebuilt = treeManifest(value.entries); if (rebuilt.digest !== digest(value.digest)) throw new TypeError("artifact manifest digest mismatch"); }
function validateChangeSet(value: ChangeSet): void { const base = { digest: value.baseManifestDigest, entries: value.base }; validateTreeManifest(base); const rebuilt = treeChangeSet(base, value.changes, value.captureOperationId); if (rebuilt.digest !== digest(value.digest)) throw new TypeError("artifact change-set digest mismatch"); }
function validateTreeEntry(entry: TreeEntry): void {
  validatePortableTreePath(entry.path); if (!Number.isSafeInteger(entry.mode) || entry.mode < 0 || entry.mode > 0o7777 || !Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > 128 * 1024 ** 3) throw new TypeError("artifact entry metadata is invalid");
  if (entry.kind === "directory") { if (entry.size !== 0 || entry.digest !== null || entry.target !== null) throw new TypeError("artifact directory entry is malformed"); return; }
  if (entry.kind === "file") { if (entry.digest === null || entry.target !== null) throw new TypeError("artifact file entry is malformed"); digest(entry.digest); return; }
  if (entry.kind !== "symlink" || entry.digest === null || entry.target === null || entry.target.length === 0 || entry.target.length > 4096 || entry.target.length !== entry.size || entry.target.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255) || createHash("sha256").update(Uint8Array.from(entry.target)).digest("hex") !== entry.digest) throw new TypeError("artifact symlink entry is malformed");
}
function validatePortableTreePath(value: string): void {
  if (value.length === 0 || value.startsWith("/") || value.endsWith("/") || value.includes("\\") || value.includes("\0") || value.normalize("NFC") !== value || value.split("/").some((part) => part.length === 0 || part === "." || part === ".." || windowsReserved(part))) throw new TypeError("artifact paths must be normalized portable relative paths");
}
function windowsReserved(value: string): boolean { const stem = (value.split(".")[0] ?? value).toUpperCase(); return value.endsWith(" ") || value.endsWith(".") || value.includes(":") || ["CON", "PRN", "AUX", "NUL"].includes(stem) || /^(?:COM|LPT)[1-9]$/u.test(stem); }
function pathDepth(path: string): number { return path.split("/").length; }
function parseTreeEntry(value: unknown): TreeEntry {
  if (!record(value) || typeof value.path !== "string" || !["directory", "file", "symlink"].includes(String(value.kind))) throw protocol("host tree entry");
  const target = value.target === null ? null : Array.isArray(value.target) && value.target.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255) ? value.target as number[] : (() => { throw protocol("host tree link target"); })();
  return { path: value.path, kind: value.kind as TreeEntry["kind"], mode: integer(value.mode), size: integer(value.size), digest: value.digest === null ? null : digest(text(value.digest)), target };
}
function parseHostCapture(value: Record<string, unknown>): ArtifactInspection {
  return { id: validateIdentity(text(value.operationId)), machineId: validateIdentity(text(value.machineId)), requestDigest: digest(text(value.requestDigest)), manifestDigest: digest(text(value.manifestDigest)), entries: integer(value.entries), bytes: integer(value.bytes), consistency: "live" };
}
function identity(prefix: string): string { return `${prefix}-${randomUUID()}`; }
function childIdentity(operationId: string, part: string): string { return `op-${sandsurfDigest("operation", ["sandsurf-child-operation-v1", validateIdentity(operationId), part]).slice(0, 48)}`; }
function validateIdentity(value: string): string { if (!/^[A-Za-z0-9_-]{1,128}$/u.test(value)) throw new TypeError("Sandsurf identity is malformed"); return value; }
function digest(value: string): string { if (!/^[a-f0-9]{64}$/u.test(value)) throw new TypeError("Sandsurf digest is malformed"); return value; }
function protocol(subject: string): SandsurfHostError { return new SandsurfHostError("protocol", `native host returned an invalid ${subject}`); }
