import { createHash, randomUUID } from "node:crypto";
import { isAbsolute, resolve } from "node:path";
import { isIP } from "node:net";
import { NativeHostClient, SandsurfHostError, integer, record, text } from "./native-host.js";
import { createSandsurfGuestPath, sandsurfDigest } from "./sandsurf-protocol.js";

export type SandsurfCapability = "spawn" | "read-files" | "write-files" | "workload-admin" | "network" | "expose-port" | "deliver-secret" | "apply-to-host" | "increase-resources" | "checkpoint" | "fork" | "release-evidence";
export type DesiredSandboxState = "running" | "paused" | "stopped" | "suspended" | "destroyed";
export interface AuthorityChange { readonly kind: "sandbox-create" | "lifecycle" | "grant" | "image-import" | "image-publish" | "image-release" | "evidence-loss" | "host-import" | "host-export" | "host-apply" | "checkpoint" | "fork" | "resource-increase" | "network-access" | "port-exposure" | "secret-delivery" | "secret-revocation"; readonly sandboxId: string; readonly operationId: string; readonly request: Readonly<Record<string, unknown>>; }
export type AuthorityDecision = boolean | { readonly approvalId: string };
export type SandsurfAuthorizer = (change: AuthorityChange) => AuthorityDecision | Promise<AuthorityDecision>;
export interface SandsurfOpenOptions { readonly directory: string; readonly authorizer?: SandsurfAuthorizer; }
export interface ResourceEnvelope { readonly vcpus: number; readonly memoryMiB: number; readonly diskBytes: number; readonly outputBytes?: number; readonly processes?: number; }
export interface SandboxCreateOptions { readonly id?: string; readonly operationId?: string; readonly image: string; readonly resources: ResourceEnvelope; readonly capabilities?: Partial<Record<SandsurfCapability, boolean>>; }
export type CheckpointKind = "filesystem" | "full";
export type CheckpointConsistency = "crash" | "filesystem" | "application";
export interface CheckpointInspection { readonly id: string; readonly operationId: string; readonly sandboxId: string; readonly expectedEpoch: number; readonly expectedRevision: number; readonly kind: CheckpointKind; readonly parent: string | null; readonly requestDigest: string; readonly phase: "admitted" | "capturing" | "ready"; readonly imageDigest: string; readonly resources: Required<ResourceEnvelope>; readonly consistency: CheckpointConsistency | null; readonly workloadDiskDigest: string | null; readonly workloadDiskBytes: number; readonly manifestDigest: string | null; readonly sensitive: boolean; }
export interface CheckpointCreateOptions { readonly id?: string; readonly operationId?: string; readonly kind?: CheckpointKind; readonly parent?: string; }
export interface DerivedImagePublishOptions { readonly operationId?: string; readonly includeWorkspace?: boolean; readonly includeHome?: boolean; readonly includeSecrets?: boolean; }
export interface SandboxForkOptions { readonly id?: string; readonly operationId?: string; readonly resources?: ResourceEnvelope; readonly capabilities?: Partial<Record<SandsurfCapability, boolean>>; }
export type Qualification = { readonly kind: "qualified"; readonly evidence: string } | { readonly kind: "unqualified"; readonly reasons: readonly string[] };
export interface HostInspection { readonly hostId: string; readonly platform: string; readonly architecture: string; readonly guestArchitecture: string; readonly guestPlatform: string; readonly engine: "firecracker" | "apple-virtualization" | "hyper-v"; readonly lifecycle: Qualification; readonly fullState: Qualification; readonly images: Qualification; readonly defaultImageDigest: string | null; }
export interface WorkloadDefaults { readonly environment: Readonly<Record<string, string>>; readonly user: string | null; readonly workingDirectory: string | null; readonly entrypoint: readonly string[]; readonly command: readonly string[]; }
export interface SandboxInspection { readonly id: string; readonly imageDigest: string; readonly resources: Required<ResourceEnvelope>; readonly runtimeConfiguration: RuntimeConfiguration; readonly configurationRevision: number; readonly reservation: "held" | "released"; readonly lifecycleIntent: Readonly<Record<string, unknown>>; readonly machine: Readonly<Record<string, unknown>>; readonly workloadDefaults: WorkloadDefaults; }
export type NetworkDestination = { readonly kind: "dns"; readonly name: string; readonly includeSubdomains?: boolean; readonly allowPrivateAddresses?: boolean } | { readonly kind: "ip"; readonly cidr: string };
export interface NetworkRule { readonly plane: "named-proxy" | "direct-tcp" | "dns"; readonly destination: NetworkDestination; readonly ports: readonly ({ readonly from: number; readonly to: number } | number)[]; }
export interface NetworkPolicy { readonly rules: readonly NetworkRule[]; }
export interface ExposureSpec { readonly guestAddress?: string; readonly guestPort: number; readonly hostAddress?: string; readonly hostPort?: number; readonly public?: boolean; }
export interface Exposure { readonly id: string; readonly sandboxId: string; readonly grantId: string; readonly revision: number; readonly spec: { readonly guestAddress: string; readonly guestPort: number; readonly hostAddress: string; readonly hostPort: number; readonly public: boolean }; readonly active: boolean; readonly boundPort: number | null; }
export interface LiveResourceLimits { readonly workloadMemoryBytes: number; readonly workloadProcesses: number; readonly cpuMax?: readonly [number, number]; }
export interface RuntimeConfiguration { readonly network: NetworkPolicy; readonly exposures: readonly Exposure[]; readonly resources: LiveResourceLimits; }
export interface ResourceUsage { readonly cpuMicros: number; readonly memoryCurrent: number; readonly memoryPeak: number; readonly diskLogicalBytes: number; readonly diskAllocatedBytes: number; readonly ioReadBytes: number; readonly ioWriteBytes: number; readonly outputRetainedBytes: number; readonly networkRxBytes: number; readonly networkTxBytes: number; readonly networkConnections: number; readonly processesCurrent: number; readonly complete: boolean; readonly source: string; readonly observedUnixMillis: number; }
export interface SecretVersion { readonly id: string; readonly version: string; readonly bytes: number; }
export interface SecretRevocation {
  readonly operationId: string;
  readonly sandboxId: string;
  readonly secret: SecretVersion;
  readonly terminateRecipients: boolean;
  readonly enforced: boolean;
  readonly evidence: null | {
    readonly filesRemoved: number;
    readonly environmentBindingsRemoved: number;
    readonly recipientsTerminated: readonly string[];
    readonly recipientsAlreadyStopped: readonly string[];
    readonly residualCopiesPossible: boolean;
    readonly enforcementComplete: boolean;
  };
}
export type OciImageSource = { readonly kind: "layout"; readonly path: string } | { readonly kind: "archive"; readonly path: string } | { readonly kind: "registry"; readonly reference: string; readonly credential?: SecretVersion };
export interface ImageImportOptions { readonly source?: OciImageSource; readonly reference?: string; readonly platform?: string; readonly operationId?: string; }
export interface ImageInspection { readonly digest: string; readonly sourceDigest: string; readonly platform: string; readonly architecture: string; readonly logicalBytes: number; readonly storageBytes: number; readonly provenanceDigest: string; readonly sensitive: boolean; }
export interface ImageReleaseInspection { readonly operationId: string; readonly imageDigest: string; readonly requestDigest: string; readonly cleanupPending: boolean; }
export interface Receipt { readonly sandboxId: string; readonly epoch: number; readonly processId: string; readonly operationId: string; readonly requestDigest: string; readonly outcome: Readonly<Record<string, unknown>>; readonly output: Readonly<Record<string, unknown>>; readonly cleanupDigest: string; readonly accountingDigest: string; }
export interface ReceiptView { readonly receipt: Receipt; readonly digest: string; }
export interface CaptureCommitment { readonly storeId: string; readonly commitmentId: string; readonly manifestDigest: string; readonly receiptDigest: string; readonly output: Readonly<Record<string, unknown>>; }
export type ReleaseDisposition = { readonly kind: "complete-capture"; readonly commitment: CaptureCommitment } | { readonly kind: "continuing-retention"; readonly pin: string } | { readonly kind: "authorized-loss"; readonly authorization?: string };
export interface ReleaseStatus { readonly requestDigest: string; readonly cleanupPending: boolean; }
export interface SandboxEvent { readonly cursor: number; readonly value: Readonly<Record<string, unknown>>; readonly digest: string; }
export interface SandboxEventPage { readonly cursor: number; readonly available: number; readonly events: readonly SandboxEvent[]; }

export class Sandsurf {
  readonly sandboxes: SandboxCollection;
  readonly images: ImageCollection;
  readonly checkpoints: CheckpointCollection;
  readonly secrets: SecretCollection;
  readonly #client: NativeHostClient;
  readonly #authorizer: SandsurfAuthorizer | undefined;
  #closed = false;
  private constructor(client: NativeHostClient, authorizer: SandsurfAuthorizer | undefined) { this.#client = client; this.#authorizer = authorizer; this.sandboxes = new SandboxCollection(this); this.images = new ImageCollection(this); this.checkpoints = new CheckpointCollection(this); this.secrets = new SecretCollection(this); }
  static async open(options: SandsurfOpenOptions): Promise<Sandsurf> { return new Sandsurf(await NativeHostClient.open(resolve(options.directory)), options.authorizer); }
  async inspect(): Promise<HostInspection> {
    this.#open(); const response = await this.#client.request({ kind: "inspect" });
    if (response.kind !== "inspection" || !record(response.value)) throw protocol("host inspection response");
    return response.value as unknown as HostInspection;
  }
  async close(): Promise<void> { this.#closed = true; }
  async request(request: Readonly<Record<string, unknown>>): Promise<Record<string, unknown>> { this.#open(); return this.#client.request(request); }
  async approve(change: AuthorityChange): Promise<string> {
    if (this.#authorizer === undefined) throw new SandsurfHostError("authorization", `No authorizer is installed for ${change.kind}`);
    const decision = await this.#authorizer(change);
    if (decision === false) throw new SandsurfHostError("authorization", `${change.kind} was denied`);
    if (decision === true) return identity("approval");
    if (!record(decision) || typeof decision.approvalId !== "string") throw new TypeError("authorizer returned an invalid decision");
    return validateIdentity(decision.approvalId);
  }
  #open(): void { if (this.#closed) throw new SandsurfHostError("client", "Sandsurf client is closed"); }
}

export class SecretCollection {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async put(id: string, bytes: string | Uint8Array, options: { readonly operationId?: string } = {}): Promise<SecretVersion> {
    const secretId = validateIdentity(id); const operationId = validateIdentity(options.operationId ?? identity("secret")); const value = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
    if (!(value instanceof Uint8Array) || value.byteLength === 0 || value.byteLength > 1024 * 1024) throw new TypeError("secret must contain 1 byte through 1 MiB");
    const version = createHash("sha256").update(value).digest("hex");
    const approvalId = await this.#host.approve({ kind: "secret-delivery", sandboxId: "host", operationId, request: { secretId, version, bytes: value.byteLength, destination: "host-capability-store" } });
    const response = await this.#host.request({ kind: "put-secret", secretId, bytes: [...value], operationId, approvalId });
    if (response.kind !== "secret" || !record(response.secret)) throw protocol("secret response");
    return parseSecret(response.secret);
  }
}

export class ImageCollection {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async importOCI(options: ImageImportOptions): Promise<SandsurfImage> {
    const operationId = validateIdentity(options.operationId ?? identity("image"));
    const inspection = await this.#host.inspect();
    const platform = options.platform ?? inspection.guestPlatform;
    const source = normalizeOciSource(options);
    const approvalId = await this.#host.approve({ kind: "image-import", sandboxId: "host", operationId, request: { source, platform } });
    const response = await this.#host.request({ kind: "import-oci", source, platform, operationId, approvalId });
    if (response.kind !== "image-import" || !record(response.operation) || !record(response.operation.image)) throw protocol("image import response");
    return new SandsurfImage(parseImage(response.operation.image));
  }
  async get(digestValue: string): Promise<SandsurfImage> {
    const response = await this.#host.request({ kind: "get-image", digest: digest(digestValue) });
    if (response.kind !== "image" || !record(response.value)) throw protocol("image response");
    return new SandsurfImage(parseImage(response.value));
  }
  async list(options: { readonly after?: string; readonly maximum?: number } = {}): Promise<readonly SandsurfImage[]> {
    const response = await this.#host.request({ kind: "list-images", after: options.after === undefined ? null : digest(options.after), maximum: options.maximum ?? 100 });
    if (response.kind !== "images" || !Array.isArray(response.values)) throw protocol("image list response");
    return response.values.map((value) => new SandsurfImage(parseImage(value)));
  }
  async release(image: string | SandsurfImage, options: { readonly operationId?: string } = {}): Promise<ImageReleaseInspection> {
    const imageDigest = digest(typeof image === "string" ? image : image.id); const operationId = validateIdentity(options.operationId ?? identity("release-image"));
    const approvalId = await this.#host.approve({ kind: "image-release", sandboxId: "host", operationId, request: { imageDigest } });
    const response = await this.#host.request({ kind: "release-image", digest: imageDigest, operationId, approvalId });
    if (response.kind !== "image-release" || !record(response.operation)) throw protocol("image release response");
    return { operationId: text(response.operation.operationId), imageDigest: digest(text(response.operation.imageDigest)), requestDigest: digest(text(response.operation.requestDigest)), cleanupPending: response.operation.cleanupPending === true };
  }
}

export class SandsurfImage {
  readonly id: string;
  readonly inspection: ImageInspection;
  constructor(inspection: ImageInspection) { this.id = inspection.digest; this.inspection = inspection; }
}

export class CheckpointCollection {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async get(id: string): Promise<SandsurfCheckpoint> {
    const response = await this.#host.request({ kind: "get-checkpoint", checkpointId: validateIdentity(id) });
    if (response.kind !== "checkpoint" || !record(response.value)) throw protocol("checkpoint response");
    return new SandsurfCheckpoint(this.#host, parseCheckpoint(response.value));
  }
  async list(options: { readonly after?: string; readonly maximum?: number } = {}): Promise<readonly SandsurfCheckpoint[]> {
    const response = await this.#host.request({ kind: "list-checkpoints", after: options.after === undefined ? null : validateIdentity(options.after), maximum: options.maximum ?? 100 });
    if (response.kind !== "checkpoints" || !Array.isArray(response.values)) throw protocol("checkpoint list response");
    return response.values.map((value) => new SandsurfCheckpoint(this.#host, parseCheckpoint(value)));
  }
}

export class SandsurfCheckpoint {
  readonly id: string;
  readonly inspection: CheckpointInspection;
  readonly #host: Sandsurf;
  constructor(host: Sandsurf, inspection: CheckpointInspection) { this.#host = host; this.inspection = inspection; this.id = inspection.id; }
  async fork(options: SandboxForkOptions = {}): Promise<Sandbox> {
    if (this.inspection.phase !== "ready" || this.inspection.kind !== "filesystem") throw new SandsurfHostError("conflict", "Only a ready filesystem checkpoint can be forked");
    const sandboxId = validateIdentity(options.id ?? identity("sandbox")); const operationId = validateIdentity(options.operationId ?? identity("fork")); const resources = normalizeResources(options.resources ?? this.inspection.resources);
    const approvalId = await this.#host.approve({ kind: "fork", sandboxId, operationId, request: { checkpointId: this.id, sourceSandboxId: this.inspection.sandboxId, resources } });
    const response = await this.#host.request({ kind: "fork-sandbox", sandboxId, checkpointId: this.id, resources, operationId, approvalId });
    const sandbox = new Sandbox(this.#host, sandboxViewFrom(response));
    for (const capability of Object.keys(options.capabilities ?? {}).sort() as SandsurfCapability[]) if (options.capabilities?.[capability] === true) await sandbox.grant(capability);
    return sandbox;
  }
  async publishImage(options: DerivedImagePublishOptions = {}): Promise<SandsurfImage> {
    if (this.inspection.phase !== "ready" || this.inspection.kind !== "filesystem") throw new SandsurfHostError("conflict", "Only a ready filesystem checkpoint can be published");
    const operationId = validateIdentity(options.operationId ?? identity("publish-image"));
    const inclusion = { workspace: options.includeWorkspace ?? false, home: options.includeHome ?? false, secrets: options.includeSecrets ?? false };
    const approvalId = await this.#host.approve({ kind: "image-publish", sandboxId: this.inspection.sandboxId, operationId, request: { checkpointId: this.id, inclusion } });
    const response = await this.#host.request({ kind: "publish-checkpoint-image", checkpointId: this.id, inclusion, operationId, approvalId });
    if (response.kind !== "image-import" || !record(response.operation) || !record(response.operation.image)) throw protocol("derived image response");
    return new SandsurfImage(parseImage(response.operation.image));
  }
}

export class SandboxCollection {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async create(options: SandboxCreateOptions): Promise<Sandbox> {
    const sandboxId = validateIdentity(options.id ?? identity("sandbox"));
    const operationId = validateIdentity(options.operationId ?? identity("create"));
    digest(options.image); const resources = normalizeResources(options.resources);
    const approvalId = await this.#host.approve({ kind: "sandbox-create", sandboxId, operationId, request: { image: options.image, resources } });
    const response = await this.#host.request({ kind: "create-sandbox", sandboxId, imageDigest: options.image, resources, operationId, approvalId });
    const sandbox = new Sandbox(this.#host, sandboxViewFrom(response));
    const capabilities = options.capabilities ?? { spawn: true, "read-files": true, "write-files": true };
    for (const capability of Object.keys(capabilities).sort() as SandsurfCapability[]) if (capabilities[capability] === true) await sandbox.grant(capability);
    return sandbox;
  }
  async connect(id: string): Promise<Sandbox> { return new Sandbox(this.#host, sandboxViewFrom(await this.#host.request({ kind: "get-sandbox", sandboxId: validateIdentity(id) }))); }
  async list(options: { readonly after?: string; readonly maximum?: number } = {}): Promise<readonly Sandbox[]> {
    const response = await this.#host.request({ kind: "list-sandboxes", after: options.after ?? null, maximum: options.maximum ?? 100 });
    if (response.kind !== "sandboxes" || !Array.isArray(response.values)) throw protocol("sandbox list response");
    return response.values.map((value) => new Sandbox(this.#host, parseView(value)));
  }
}

export class Sandbox {
  readonly id: string;
  readonly processes: ProcessCollection;
  readonly terminals: TerminalCollection;
  readonly fs: SandboxFilesystem;
  readonly workspace: SandboxWorkspace;
  readonly operations: SandboxOperations;
  readonly events: SandboxEvents;
  readonly network: SandboxNetwork;
  readonly ports: SandboxPorts;
  readonly resources: SandboxResources;
  readonly secrets: SandboxSecrets;
  readonly checkpoints: SandboxCheckpoints;
  readonly #host: Sandsurf;
  #view: SandboxInspection;
  constructor(host: Sandsurf, view: SandboxInspection) { this.#host = host; this.#view = view; this.id = view.id; this.processes = new ProcessCollection(this); this.terminals = new TerminalCollection(this); this.fs = new SandboxFilesystem(this); this.workspace = new SandboxWorkspace(this); this.operations = new SandboxOperations(this); this.events = new SandboxEvents(this); this.network = new SandboxNetwork(this); this.ports = new SandboxPorts(this); this.resources = new SandboxResources(this); this.secrets = new SandboxSecrets(this); this.checkpoints = new SandboxCheckpoints(this, host); }
  get revision(): number { return this.#view.configurationRevision; }
  retainedOutput(pinId: string): PinnedOutput { return new PinnedOutput(this, validateIdentity(pinId)); }
  async inspect(): Promise<SandboxInspection> { this.#view = sandboxViewFrom(await this.#host.request({ kind: "get-sandbox", sandboxId: this.id })); return this.#view; }
  async start(operationId = identity("start")): Promise<SandboxInspection> { return this.#lifecycle("running", operationId); }
  async stop(operationId = identity("stop")): Promise<SandboxInspection> { return this.#lifecycle("stopped", operationId); }
  async pause(operationId = identity("pause")): Promise<SandboxInspection> { return this.#lifecycle("paused", operationId); }
  async resume(operationId = identity("resume")): Promise<SandboxInspection> { return this.#lifecycle("running", operationId); }
  async suspend(operationId = identity("suspend")): Promise<SandboxInspection> { return this.#lifecycle("suspended", operationId); }
  async destroy(operationId = identity("destroy")): Promise<SandboxInspection> { return this.#lifecycle("destroyed", operationId); }
  async grant(capability: SandsurfCapability, options: { readonly scopeDigest?: string; readonly operationId?: string } = {}): Promise<void> {
    const scopeDigest = options.scopeDigest ?? capabilityScope(this.id, capability); const operationId = validateIdentity(options.operationId ?? identity("grant")); const view = await this.inspect();
    const approvalId = await this.#host.approve({ kind: "grant", sandboxId: this.id, operationId, request: { capability, scopeDigest, expectedRevision: view.configurationRevision } });
    const response = await this.#host.request({ kind: "set-grant", sandboxId: this.id, grantId: identity("grant"), expectedRevision: view.configurationRevision, capability, scopeDigest, revoked: false, approvalId });
    if (response.kind !== "grant" || !record(response.grant)) throw protocol("grant response");
    this.#view = { ...this.#view, configurationRevision: integer(response.grant.revision) };
  }
  async workload(request: Readonly<Record<string, unknown>>, capability: SandsurfCapability, operationId: string): Promise<Record<string, unknown>> {
    const view = await this.inspect(); const machine = currentMachine(view);
    const response = await this.#host.request({ kind: "workload", sandboxId: this.id, epoch: machine.epoch, operationId, expectedRevision: view.configurationRevision, request, scopeDigest: capabilityScope(this.id, capability) });
    if (response.kind !== "dispatch" || !record(response.operation)) throw protocol("workload dispatch response");
    return response.operation;
  }
  async guest(request: Readonly<Record<string, unknown>>, capability: SandsurfCapability): Promise<Record<string, unknown>> {
    const view = await this.inspect();
    const response = await this.#host.request({ kind: "guest", sandboxId: this.id, expectedRevision: view.configurationRevision, capability, scopeDigest: capabilityScope(this.id, capability), request });
    if (response.kind !== "guest" || !record(response.response)) throw protocol("guest response");
    return response.response;
  }
  async hostRequest(request: Readonly<Record<string, unknown>>): Promise<Record<string, unknown>> { return this.#host.request(request); }
  async approve(change: AuthorityChange): Promise<string> { return this.#host.approve(change); }
  async #lifecycle(desired: DesiredSandboxState, operationId: string): Promise<SandboxInspection> {
    validateIdentity(operationId); const view = await this.inspect(); const approvalId = await this.#host.approve({ kind: "lifecycle", sandboxId: this.id, operationId, request: { desired, expectedRevision: view.configurationRevision } });
    this.#view = sandboxViewFrom(await this.#host.request({ kind: "lifecycle", sandboxId: this.id, operationId, expectedRevision: view.configurationRevision, desired, approvalId })); return this.#view;
  }
}

export class SandboxCheckpoints {
  readonly #sandbox: Sandbox;
  readonly #host: Sandsurf;
  constructor(sandbox: Sandbox, host: Sandsurf) { this.#sandbox = sandbox; this.#host = host; }
  async create(options: CheckpointCreateOptions = {}): Promise<SandsurfCheckpoint> {
    const id = validateIdentity(options.id ?? identity("checkpoint")); const operationId = validateIdentity(options.operationId ?? identity("checkpoint")); const view = await this.#sandbox.inspect(); const machine = currentMachine(view); const kind = options.kind ?? "filesystem";
    if (kind !== "filesystem" && kind !== "full") throw new TypeError("checkpoint kind is invalid");
    const parent = options.parent === undefined ? null : validateIdentity(options.parent); const request = { id, operationId, sandboxId: this.#sandbox.id, expectedEpoch: machine.epoch, expectedRevision: view.configurationRevision, kind, parent };
    const approvalId = await this.#sandbox.approve({ kind: "checkpoint", sandboxId: this.#sandbox.id, operationId, request });
    const response = await this.#sandbox.hostRequest({ kind: "create-checkpoint", request, scopeDigest: capabilityScope(this.#sandbox.id, "checkpoint"), approvalId });
    if (response.kind !== "checkpoint" || !record(response.value)) throw protocol("checkpoint response");
    return new SandsurfCheckpoint(this.#host, parseCheckpoint(response.value));
  }
  async rollback(checkpointId: string, options: { readonly operationId?: string } = {}): Promise<Readonly<Record<string, unknown>>> {
    const id = validateIdentity(checkpointId); const operationId = validateIdentity(options.operationId ?? identity("rollback")); const view = await this.#sandbox.inspect();
    const approvalId = await this.#sandbox.approve({ kind: "checkpoint", sandboxId: this.#sandbox.id, operationId, request: { action: "rollback", checkpointId: id, expectedRevision: view.configurationRevision } });
    const response = await this.#sandbox.hostRequest({ kind: "rollback-filesystem", sandboxId: this.#sandbox.id, checkpointId: id, operationId, expectedRevision: view.configurationRevision, scopeDigest: capabilityScope(this.#sandbox.id, "checkpoint"), approvalId });
    if (response.kind !== "rollback" || !record(response.value)) throw protocol("rollback response");
    return response.value;
  }
}

export class SandboxNetwork {
  readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox) { this.#sandbox = sandbox; }
  async configure(policy: NetworkPolicy, options: { readonly operationId?: string } = {}): Promise<RuntimeConfiguration> {
    const normalized = normalizeNetworkPolicy(policy); const operationId = validateIdentity(options.operationId ?? identity("network")); const view = await this.#sandbox.inspect();
    const approvalId = await this.#sandbox.approve({ kind: "network-access", sandboxId: this.#sandbox.id, operationId, request: { expectedRevision: view.configurationRevision, policy: normalized } });
    const response = await this.#sandbox.hostRequest({ kind: "set-network-policy", sandboxId: this.#sandbox.id, operationId, expectedRevision: view.configurationRevision, policy: normalized, approvalId });
    if (response.kind !== "configuration" || !record(response.sandbox)) throw protocol("network configuration response");
    return parseView(response.sandbox).runtimeConfiguration;
  }
  async denyAll(options: { readonly operationId?: string } = {}): Promise<RuntimeConfiguration> { return this.configure({ rules: [] }, options); }
  async inspect(): Promise<NetworkPolicy> { return (await this.#sandbox.inspect()).runtimeConfiguration.network; }
}

export class SandboxPorts {
  readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox) { this.#sandbox = sandbox; }
  async expose(spec: ExposureSpec, options: { readonly id?: string; readonly operationId?: string } = {}): Promise<Exposure> {
    const exposureId = validateIdentity(options.id ?? identity("exposure")); const operationId = validateIdentity(options.operationId ?? identity("expose")); const view = await this.#sandbox.inspect();
    const normalized = normalizeExposure(spec);
    const approvalId = await this.#sandbox.approve({ kind: "port-exposure", sandboxId: this.#sandbox.id, operationId, request: { exposureId, expectedRevision: view.configurationRevision, spec: normalized, active: true } });
    const response = await this.#sandbox.hostRequest({ kind: "set-exposure", sandboxId: this.#sandbox.id, operationId, expectedRevision: view.configurationRevision, exposureId, spec: normalized, active: true, approvalId });
    if (response.kind !== "exposure" || !record(response.exposure)) throw protocol("port exposure response");
    return parseExposure(response.exposure);
  }
  async revoke(id: string, options: { readonly operationId?: string } = {}): Promise<Exposure> {
    const exposureId = validateIdentity(id); const operationId = validateIdentity(options.operationId ?? identity("unexpose")); const view = await this.#sandbox.inspect(); const existing = view.runtimeConfiguration.exposures.find((value) => value.id === exposureId);
    if (existing === undefined) throw new SandsurfHostError("missing", `Exposure ${exposureId} does not exist`);
    const approvalId = await this.#sandbox.approve({ kind: "port-exposure", sandboxId: this.#sandbox.id, operationId, request: { exposureId, expectedRevision: view.configurationRevision, spec: existing.spec, active: false } });
    const response = await this.#sandbox.hostRequest({ kind: "set-exposure", sandboxId: this.#sandbox.id, operationId, expectedRevision: view.configurationRevision, exposureId, spec: existing.spec, active: false, approvalId });
    if (response.kind !== "exposure" || !record(response.exposure)) throw protocol("port exposure revocation response");
    return parseExposure(response.exposure);
  }
  async list(): Promise<readonly Exposure[]> { return (await this.#sandbox.inspect()).runtimeConfiguration.exposures; }
}

export class SandboxResources {
  readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox) { this.#sandbox = sandbox; }
  async usage(): Promise<ResourceUsage> {
    const response = await this.#sandbox.hostRequest({ kind: "get-usage", sandboxId: this.#sandbox.id });
    if (response.kind !== "usage" || !record(response.usage)) throw protocol("resource usage response");
    return parseUsage(response.usage);
  }
  async update(resources: ResourceEnvelope, live: LiveResourceLimits, options: { readonly operationId?: string } = {}): Promise<SandboxInspection> {
    const operationId = validateIdentity(options.operationId ?? identity("resources")); const view = await this.#sandbox.inspect(); const normalized = normalizeResources(resources); const limits = normalizeLiveResources(live);
    const approvalId = await this.#sandbox.approve({ kind: "resource-increase", sandboxId: this.#sandbox.id, operationId, request: { expectedRevision: view.configurationRevision, resources: normalized, live: limits } });
    const response = await this.#sandbox.hostRequest({ kind: "update-resources", sandboxId: this.#sandbox.id, operationId, expectedRevision: view.configurationRevision, resources: normalized, live: limits, approvalId });
    if (response.kind !== "configuration" || !record(response.sandbox)) throw protocol("resource update response");
    return parseView(response.sandbox);
  }
}

export class SandboxSecrets {
  readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox) { this.#sandbox = sandbox; }
  async deliver(secret: SecretVersion, options: { readonly path?: string | Uint8Array; readonly mode?: number; readonly environment?: string; readonly processId?: string; readonly lifetime?: "process" | "sandbox" | "until-revoked"; readonly operationId?: string } = {}): Promise<SecretVersion> {
    const parsed = parseSecret(secret as unknown as Record<string, unknown>); const operationId = validateIdentity(options.operationId ?? identity("deliver")); const view = await this.#sandbox.inspect(); let destination: Readonly<Record<string, unknown>>;
    if (options.environment !== undefined) { if (!/^[A-Za-z0-9_]{1,4096}$/u.test(options.environment)) throw new TypeError("secret environment name is malformed"); destination = { kind: "environment", name: options.environment }; }
    else { const path = options.path ?? `/run/sandsurf-secrets/${parsed.id}`; destination = { kind: "file", path: [...createSandsurfGuestPath(path)], mode: options.mode ?? 0o600 }; }
    const lifetime = options.lifetime ?? (options.processId === undefined ? "sandbox" : "process"); const processId = options.processId === undefined ? null : validateIdentity(options.processId); const delivery = { secret: parsed, destination, lifetime, processId };
    const approvalId = await this.#sandbox.approve({ kind: "secret-delivery", sandboxId: this.#sandbox.id, operationId, request: { expectedRevision: view.configurationRevision, delivery } });
    const response = await this.#sandbox.hostRequest({ kind: "deliver-secret", sandboxId: this.#sandbox.id, operationId, expectedRevision: view.configurationRevision, scopeDigest: capabilityScope(this.#sandbox.id, "deliver-secret"), delivery, approvalId });
    if (response.kind !== "secret" || !record(response.secret)) throw protocol("secret delivery response");
    return parseSecret(response.secret);
  }
  async revoke(secret: SecretVersion, options: { readonly terminateRecipients?: boolean; readonly operationId?: string } = {}): Promise<SecretRevocation> {
    const parsed = parseSecret(secret as unknown as Record<string, unknown>); const operationId = validateIdentity(options.operationId ?? identity("revoke-secret")); const view = await this.#sandbox.inspect(); const terminateRecipients = options.terminateRecipients ?? true;
    const approvalId = await this.#sandbox.approve({ kind: "secret-revocation", sandboxId: this.#sandbox.id, operationId, request: { expectedRevision: view.configurationRevision, secret: parsed, terminateRecipients } });
    const response = await this.#sandbox.hostRequest({ kind: "revoke-secret", sandboxId: this.#sandbox.id, operationId, expectedRevision: view.configurationRevision, secret: parsed, terminateRecipients, approvalId });
    if (response.kind !== "secret-revocation" || !record(response.revocation)) throw protocol("secret revocation response");
    return parseSecretRevocation(response.revocation);
  }
}

export class SandboxOperations {
  readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox) { this.#sandbox = sandbox; }
  async get(operationId: string): Promise<Readonly<Record<string, unknown>> | undefined> {
    const response = await this.#sandbox.hostRequest({ kind: "get-operation", sandboxId: this.#sandbox.id, operationId: validateIdentity(operationId) });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "operation") throw protocol("operation response");
    return response.response.operation === null ? undefined : record(response.response.operation) ? response.response.operation : (() => { throw protocol("operation record"); })();
  }
}

export class SandboxEvents {
  readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox) { this.#sandbox = sandbox; }
  async read(options: { readonly after?: number; readonly maximum?: number } = {}): Promise<SandboxEventPage> {
    const after = options.after ?? 0; const maximum = options.maximum ?? 256;
    if (!Number.isSafeInteger(after) || after < 0) throw new TypeError("event cursor must be a non-negative safe integer");
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 256) throw new TypeError("event page maximum must be 1 through 256");
    const response = await this.#sandbox.hostRequest({ kind: "list-events", sandboxId: this.#sandbox.id, after, maximum });
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
  async *follow(options: { readonly after?: number; readonly maximum?: number; readonly pollMs?: number; readonly signal?: AbortSignal } = {}): AsyncGenerator<SandboxEvent, void> {
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
export interface SpawnOptions { readonly operationId?: string; readonly processId?: string; readonly argv: readonly string[]; readonly cwd?: string; readonly environment?: Readonly<Record<string, string>>; readonly user?: string; readonly stdio?: "pipes" | "terminal"; readonly terminalSize?: TerminalSize; readonly lifetime?: "job" | "sandbox"; readonly deadlineMs?: number; readonly outputBytes?: number; }
export type ExecOptions = Omit<SpawnOptions, "lifetime"> & { readonly signal?: AbortSignal; readonly pollMs?: number };
export type ShellOptions = Omit<SpawnOptions, "argv"> & { readonly shell?: string };
export type ExecShellOptions = Omit<ExecOptions, "argv"> & { readonly shell?: string };
export interface ExecResult { readonly process: SandboxProcess; readonly inspection: ProcessInspection; }
export interface ProcessInspection { readonly request: Readonly<Record<string, unknown>>; readonly guestPid: number; readonly state: Readonly<Record<string, unknown>>; readonly lineage: Readonly<Record<string, unknown>> | null; }
export type ProcessObservation = { readonly kind: "current"; readonly value: ProcessInspection } | { readonly kind: "unavailable"; readonly lastKnown: ProcessInspection | null };

export class ProcessCollection {
  readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox) { this.#sandbox = sandbox; }
  async spawn(options: SpawnOptions): Promise<SandboxProcess> {
    const operationId = validateIdentity(options.operationId ?? identity("spawn")); const processId = validateIdentity(options.processId ?? identity("process"));
    const view = await this.#sandbox.inspect(); const machine = currentMachine(view); const stdio = options.stdio ?? "pipes";
    const terminalSize = stdio === "terminal" ? { columns: options.terminalSize?.columns ?? 80, rows: options.terminalSize?.rows ?? 24, pixelWidth: options.terminalSize?.pixelWidth ?? 0, pixelHeight: options.terminalSize?.pixelHeight ?? 0 } : null;
    const user = options.user ?? view.workloadDefaults.user ?? "root"; const proxy = view.runtimeConfiguration.network.rules.some((rule) => rule.plane === "named-proxy") ? { HTTP_PROXY: "http://127.0.0.1:3128", HTTPS_PROXY: "http://127.0.0.1:3128", http_proxy: "http://127.0.0.1:3128", https_proxy: "http://127.0.0.1:3128", ALL_PROXY: "socks5h://127.0.0.1:1080", all_proxy: "socks5h://127.0.0.1:1080", NO_PROXY: "localhost,127.0.0.1,::1", no_proxy: "localhost,127.0.0.1,::1" } : {};
    const deadlineMillis = options.deadlineMs ?? null; if (deadlineMillis !== null && (!Number.isSafeInteger(deadlineMillis) || deadlineMillis <= 0 || deadlineMillis > 30 * 24 * 60 * 60 * 1000)) throw new TypeError("process deadline must be a positive safe integer no greater than 30 days");
    const operation = await this.#sandbox.workload({ kind: "spawn", request: { sandboxId: this.#sandbox.id, epoch: machine.epoch, processId, operationId, argv: [...options.argv], cwd: options.cwd ?? view.workloadDefaults.workingDirectory ?? "/workspace", environment: { ...proxy, ...view.workloadDefaults.environment, ...(options.environment ?? {}) }, user, stdio, terminalSize, lifetime: options.lifetime ?? "job", deadlineMillis, outputBytes: options.outputBytes ?? 64 * 1024 * 1024 } }, user === "root" || user === "0" || user.startsWith("0:") ? "workload-admin" : "spawn", operationId);
    if (operation.delivery === "not-applied") throw new SandsurfHostError("workload", `Process ${processId} was not applied`);
    return new SandboxProcess(this.#sandbox, processId);
  }
  async exec(options: ExecOptions): Promise<ExecResult> {
    const { signal, pollMs, ...spawn } = options;
    const process = await this.spawn({ ...spawn, lifetime: "job" });
    return { process, inspection: await process.wait({ ...(signal === undefined ? {} : { signal }), ...(pollMs === undefined ? {} : { pollMs }) }) };
  }
  spawnShell(command: string, options: ShellOptions = {}): Promise<SandboxProcess> {
    if (command.length === 0 || command.length > 1024 * 1024) throw new TypeError("shell command is empty or oversized");
    const { shell = "/bin/sh", ...spawn } = options;
    return this.spawn({ ...spawn, argv: [shell, "-lc", command] });
  }
  execShell(command: string, options: ExecShellOptions = {}): Promise<ExecResult> {
    if (command.length === 0 || command.length > 1024 * 1024) throw new TypeError("shell command is empty or oversized");
    const { shell = "/bin/sh", ...exec } = options;
    return this.exec({ ...exec, argv: [shell, "-lc", command] });
  }
  async get(id: string): Promise<SandboxProcess> { const process = new SandboxProcess(this.#sandbox, validateIdentity(id)); await process.inspect(); return process; }
  async list(): Promise<readonly ProcessObservation[]> {
    const response = await this.#sandbox.hostRequest({ kind: "list-processes", sandboxId: this.#sandbox.id });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "processes" || !Array.isArray(response.response.processes)) throw protocol("process list response");
    return response.response.processes.map(parseProcessObservation);
  }
}

export type TerminalOpenOptions = Omit<SpawnOptions, "stdio" | "terminalSize"> & { readonly terminalSize?: TerminalSize; readonly inputLeaseId?: string };

export class TerminalCollection {
  readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox) { this.#sandbox = sandbox; }
  async open(options: TerminalOpenOptions): Promise<SandboxTerminal> {
    const { inputLeaseId, ...spawn } = options;
    const process = await this.#sandbox.processes.spawn({ ...spawn, stdio: "terminal", ...(options.terminalSize === undefined ? {} : { terminalSize: options.terminalSize }) });
    const terminal = new SandboxTerminal(process);
    await terminal.acquireInput(inputLeaseId);
    return terminal;
  }
  async get(id: string): Promise<SandboxTerminal> {
    const process = await this.#sandbox.processes.get(id);
    const observed = await process.inspect();
    if (observed.kind !== "current" || observed.value.request.stdio !== "terminal") throw new SandsurfHostError("conflict", `Process ${process.id} is not a terminal`);
    return new SandboxTerminal(process);
  }
}

export class SandboxTerminal {
  readonly id: string;
  readonly output: ProcessOutput;
  readonly process: SandboxProcess;
  #attached = true;
  #inputLeaseId: string | undefined;
  constructor(process: SandboxProcess) { this.process = process; this.id = process.id; this.output = process.output; }
  async acquireInput(leaseId = identity("terminal-input")): Promise<string> { this.#requireAttached(); const id = validateIdentity(leaseId); await this.process.acquireTerminalInput(id); this.#inputLeaseId = id; return id; }
  async releaseInput(): Promise<void> { this.#requireAttached(); if (this.#inputLeaseId !== undefined) { const lease = this.#inputLeaseId; await this.process.releaseTerminalInput(lease); this.#inputLeaseId = undefined; } }
  async detach(): Promise<void> { if (this.#attached) { await this.releaseInput(); this.#attached = false; } }
  inspect(): Promise<ProcessObservation> { this.#requireAttached(); return this.process.inspect(); }
  wait(options: { readonly pollMs?: number; readonly signal?: AbortSignal } = {}): Promise<ProcessInspection> { this.#requireAttached(); return this.process.wait(options); }
  write(bytes: Uint8Array, operationId?: string): Promise<void> { this.#requireAttached(); if (this.#inputLeaseId === undefined) throw new SandsurfHostError("conflict", `Terminal ${this.id} has no input lease`); return this.process.write(bytes, operationId, this.#inputLeaseId); }
  closeInput(operationId?: string): Promise<void> { this.#requireAttached(); if (this.#inputLeaseId === undefined) throw new SandsurfHostError("conflict", `Terminal ${this.id} has no input lease`); return this.process.closeInput(operationId, this.#inputLeaseId); }
  resize(size: TerminalSize, operationId?: string): Promise<void> { this.#requireAttached(); return this.process.resize(size, operationId); }
  signal(signal: number, group = true, operationId?: string): Promise<void> { this.#requireAttached(); return this.process.signal(signal, group, operationId); }
  terminate(graceMillis = 1000, operationId?: string): Promise<void> { this.#requireAttached(); return this.process.terminate(graceMillis, operationId); }
  #requireAttached(): void { if (!this.#attached) throw new SandsurfHostError("client", `Terminal ${this.id} is detached`); }
}

export interface OutputChunk { readonly cursor: number; readonly stream: "stdout" | "stderr" | "terminal"; readonly bytes: Uint8Array; readonly digest: string; }
export interface OutputPage { readonly after: number; readonly available: number; readonly chunks: readonly OutputChunk[]; readonly requiredBytes?: number; }

export class SandboxProcess {
  readonly id: string; readonly output: ProcessOutput; readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox, id: string) { this.#sandbox = sandbox; this.id = id; this.output = new ProcessOutput(this); }
  async inspect(): Promise<ProcessObservation> { const response = await this.#sandbox.hostRequest({ kind: "get-process", sandboxId: this.#sandbox.id, processId: this.id }); if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "process") throw protocol("process response"); if (response.response.process === null) throw new SandsurfHostError("missing", `Process ${this.id} does not exist`); return parseProcessObservation(response.response.process); }
  async wait(options: { readonly pollMs?: number; readonly signal?: AbortSignal } = {}): Promise<ProcessInspection> {
    if (options.signal?.aborted === true) throw options.signal.reason;
    const boundary = await this.#sandbox.events.read({ maximum: 1 });
    const observed = await this.inspect();
    if (observed.kind !== "current") throw new SandsurfHostError("unavailable", `Process ${this.id} is not currently observable`);
    if (observed.value.state.kind !== "running") return observed.value;
    for await (const event of this.#sandbox.events.follow({ after: boundary.available, ...(options.pollMs === undefined ? {} : { pollMs: options.pollMs }), ...(options.signal === undefined ? {} : { signal: options.signal }) })) {
      if (event.value.kind !== "process" || !record(event.value.process)) continue;
      const process = parseProcess(event.value.process);
      if (process.request.processId === this.id && process.state.kind !== "running") return process;
    }
    if (options.signal !== undefined) throw options.signal.reason;
    throw new SandsurfHostError("unavailable", `Process ${this.id} event stream ended`);
  }
  async readOutput(options: { readonly after?: number; readonly maximum?: number } = {}): Promise<OutputPage> {
    const { after, maximum } = normalizeOutputRead(options);
    const response = await this.#sandbox.hostRequest({ kind: "read-evidence", sandboxId: this.#sandbox.id, processId: this.id, after, maximum });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "output" || !record(response.response.page) || !Array.isArray(response.response.page.chunks)) throw protocol("output response");
    return parseEvidencePage(response.response.page);
  }
  async receipt(): Promise<ReceiptView | undefined> {
    const response = await this.#sandbox.hostRequest({ kind: "get-receipt", sandboxId: this.#sandbox.id, processId: this.id });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "receipt") throw protocol("receipt response");
    if (response.response.receipt === null && response.response.digest === null) return undefined;
    if (!record(response.response.receipt) || typeof response.response.digest !== "string") throw protocol("receipt record");
    return { receipt: response.response.receipt as unknown as Receipt, digest: digest(response.response.digest) };
  }
  async acknowledge(receiptDigest: string): Promise<void> { await this.#evidenceMutation("acknowledge-receipt", { receiptDigest: digest(receiptDigest) }); }
  async pin(pinId: string, receiptDigest: string): Promise<PinnedOutput> { const id = validateIdentity(pinId); await this.#evidenceMutation("pin-evidence", { pinId: id, receiptDigest: digest(receiptDigest) }); return new PinnedOutput(this.#sandbox, id); }
  async release(receipt: ReceiptView, disposition: ReleaseDisposition): Promise<ReleaseStatus> {
    const view = await this.#sandbox.inspect(); let lossApprovalId: string | null = null; let normalized: Readonly<Record<string, unknown>>;
    if (disposition.kind === "complete-capture") normalized = { kind: disposition.kind, commitment: disposition.commitment };
    else if (disposition.kind === "continuing-retention") normalized = { kind: disposition.kind, pin: validateIdentity(disposition.pin) };
    else { const operationId = identity("loss"); lossApprovalId = disposition.authorization === undefined ? await this.#sandbox.approve({ kind: "evidence-loss", sandboxId: this.#sandbox.id, operationId, request: { processId: this.id, receiptDigest: receipt.digest, output: receipt.receipt.output } }) : validateIdentity(disposition.authorization); normalized = { kind: disposition.kind, authorization: lossApprovalId }; }
    const response = await this.#sandbox.hostRequest({ kind: "release-evidence", sandboxId: this.#sandbox.id, processId: this.id, request: { receiptDigest: receipt.digest, output: receipt.receipt.output, disposition: normalized }, expectedRevision: view.configurationRevision, scopeDigest: capabilityScope(this.#sandbox.id, "release-evidence"), lossApprovalId });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "release" || !record(response.response.status)) throw protocol("release response");
    return parseReleaseStatus(response.response.status);
  }
  async cleanupReleased(requestDigest: string): Promise<ReleaseStatus> {
    const response = await this.#sandbox.hostRequest({ kind: "cleanup-released-evidence", sandboxId: this.#sandbox.id, processId: this.id, requestDigest: digest(requestDigest) });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "release" || !record(response.response.status)) throw protocol("release cleanup response");
    return parseReleaseStatus(response.response.status);
  }
  async acquireTerminalInput(terminalLeaseId: string, operationId = identity("acquire-input")): Promise<void> { await this.#sandbox.workload({ kind: "acquire-terminal-input", processId: this.id, terminalLeaseId: validateIdentity(terminalLeaseId) }, "spawn", operationId); }
  async releaseTerminalInput(terminalLeaseId: string, operationId = identity("release-input")): Promise<void> { await this.#sandbox.workload({ kind: "release-terminal-input", processId: this.id, terminalLeaseId: validateIdentity(terminalLeaseId) }, "spawn", operationId); }
  async write(bytes: Uint8Array, operationId = identity("input"), terminalLeaseId: string | null = null): Promise<void> { await this.#sandbox.workload({ kind: "write-input", processId: this.id, terminalLeaseId: terminalLeaseId === null ? null : validateIdentity(terminalLeaseId), bytes: [...bytes] }, "spawn", operationId); }
  async closeInput(operationId = identity("close"), terminalLeaseId: string | null = null): Promise<void> { await this.#sandbox.workload({ kind: "close-input", processId: this.id, terminalLeaseId: terminalLeaseId === null ? null : validateIdentity(terminalLeaseId) }, "spawn", operationId); }
  async signal(signal: number, group = true, operationId = identity("signal")): Promise<void> { await this.#sandbox.workload({ kind: "signal", processId: this.id, signal, group }, "spawn", operationId); }
  async terminate(graceMillis = 1000, operationId = identity("terminate")): Promise<void> { await this.#sandbox.workload({ kind: "terminate", processId: this.id, graceMillis }, "spawn", operationId); }
  async resize(size: TerminalSize, operationId = identity("resize")): Promise<void> { await this.#sandbox.workload({ kind: "resize-terminal", processId: this.id, size: { columns: size.columns, rows: size.rows, pixelWidth: size.pixelWidth ?? 0, pixelHeight: size.pixelHeight ?? 0 } }, "spawn", operationId); }
  async #evidenceMutation(kind: "acknowledge-receipt" | "pin-evidence", fields: Readonly<Record<string, unknown>>): Promise<void> {
    const view = await this.#sandbox.inspect(); const response = await this.#sandbox.hostRequest({ kind, sandboxId: this.#sandbox.id, processId: this.id, ...fields, expectedRevision: view.configurationRevision, scopeDigest: capabilityScope(this.#sandbox.id, "release-evidence") });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "complete") throw protocol("evidence mutation response");
  }
}

export class ProcessOutput {
  readonly #process: SandboxProcess;
  constructor(process: SandboxProcess) { this.#process = process; }
  read(options: { readonly after?: number; readonly maximum?: number } = {}): Promise<OutputPage> { return this.#process.readOutput(options); }
  async *follow(options: { readonly after?: number; readonly maximum?: number; readonly pollMs?: number; readonly signal?: AbortSignal } = {}): AsyncGenerator<OutputChunk, void, void> {
    let cursor = options.after ?? 0;
    for (;;) {
      if (options.signal?.aborted === true) throw options.signal.reason;
      const page = await this.read({ after: cursor, ...(options.maximum === undefined ? {} : { maximum: options.maximum }) });
      for (const chunk of page.chunks) { cursor = chunk.cursor + chunk.bytes.byteLength; yield chunk; }
      const receipt = await this.#process.receipt();
      if (receipt !== undefined && cursor >= integer(receipt.receipt.output.finalCursor)) return;
      if (page.chunks.length === 0) await new Promise((done) => setTimeout(done, options.pollMs ?? 50));
    }
  }
}

export class PinnedOutput {
  readonly id: string; readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox, id: string) { this.#sandbox = sandbox; this.id = id; }
  async read(options: { readonly after?: number; readonly maximum?: number } = {}): Promise<OutputPage> {
    const { after, maximum } = normalizeOutputRead(options);
    const response = await this.#sandbox.hostRequest({ kind: "read-pinned-evidence", sandboxId: this.#sandbox.id, pinId: this.id, after, maximum });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "output" || !record(response.response.page)) throw protocol("pinned output response");
    return parseEvidencePage(response.response.page);
  }
}

export type FileExpectation = { readonly kind: "any" } | { readonly kind: "absent" } | { readonly kind: "matches"; readonly size: number; readonly digest: string };
export type FileTransactionMutation =
  | { readonly kind: "write"; readonly path: string | Uint8Array; readonly bytes: string | Uint8Array; readonly mode?: number; readonly expected?: FileExpectation }
  | { readonly kind: "remove"; readonly path: string | Uint8Array; readonly expected?: FileExpectation };
export class SandboxFilesystem {
  readonly #sandbox: Sandbox; constructor(sandbox: Sandbox) { this.#sandbox = sandbox; }
  stat(path: string | Uint8Array, follow = true): Promise<Record<string, unknown>> { return this.#operation({ kind: "stat", path: [...createSandsurfGuestPath(path)], follow }, "read-files"); }
  lstat(path: string | Uint8Array): Promise<Record<string, unknown>> { return this.stat(path, false); }
  list(path: string | Uint8Array, options: { readonly after?: Uint8Array; readonly maximum?: number } = {}): Promise<Record<string, unknown>> { return this.#operation({ kind: "list", path: [...createSandsurfGuestPath(path)], after: options.after === undefined ? null : [...options.after], maximum: options.maximum ?? 256 }, "read-files"); }
  read(path: string | Uint8Array, offset = 0, maximum = 64 * 1024): Promise<Record<string, unknown>> { return this.#operation({ kind: "read", path: [...createSandsurfGuestPath(path)], offset, maximum }, "read-files"); }
  async readFile(path: string | Uint8Array): Promise<Uint8Array> {
    const guestPath = createSandsurfGuestPath(path); const chunks: Uint8Array[] = []; let offset = 0; let revision: { readonly size: number; readonly digest: string } | undefined;
    for (;;) { const response = await this.read(Uint8Array.from(guestPath), offset); if (response.kind !== "read" || !record(response.range) || !record(response.range.revision) || !Array.isArray(response.range.bytes) || integer(response.range.offset) !== offset) throw protocol("file range response"); const observed = { size: integer(response.range.revision.size), digest: digest(text(response.range.revision.digest)) }; if (revision !== undefined && (observed.size !== revision.size || observed.digest !== revision.digest)) throw new SandsurfHostError("conflict", "file changed during streamed read"); revision = observed; const bytes = Uint8Array.from(response.range.bytes as number[]); chunks.push(bytes); offset += bytes.byteLength; if (response.range.eof === true) break; if (bytes.byteLength === 0) throw protocol("empty non-terminal file range"); }
    const result = new Uint8Array(offset); let cursor = 0; for (const chunk of chunks) { result.set(chunk, cursor); cursor += chunk.byteLength; } if (revision === undefined || revision.size !== result.byteLength || createHash("sha256").update(result).digest("hex") !== revision.digest) throw new SandsurfHostError("integrity", "file bytes do not match their revision"); return result;
  }
  async writeFile(path: string | Uint8Array, bytes: string | Uint8Array, options: { readonly mode?: number; readonly expected?: FileExpectation } = {}): Promise<Record<string, unknown>> {
    const value = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
    return this.writeStream(path, [value], { length: value.byteLength, digest: createHash("sha256").update(value).digest("hex"), ...options });
  }
  async transaction(mutations: readonly FileTransactionMutation[], options: { readonly operationId?: string } = {}): Promise<void> {
    const operationId = validateIdentity(options.operationId ?? identity("file-transaction"));
    const normalized = mutations.map((mutation) => mutation.kind === "write"
      ? { kind: "write", path: [...createSandsurfGuestPath(mutation.path)], bytes: [...(typeof mutation.bytes === "string" ? new TextEncoder().encode(mutation.bytes) : mutation.bytes)], mode: mutation.mode ?? 0o644, expected: mutation.expected ?? { kind: "any" } }
      : { kind: "remove", path: [...createSandsurfGuestPath(mutation.path)], expected: mutation.expected ?? { kind: "any" } });
    await this.#operation({ kind: "transaction", transaction: { id: operationId, mutations: normalized } }, "write-files", operationId);
  }
  async writeStream(path: string | Uint8Array, chunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>, options: { readonly length: number; readonly digest: string; readonly mode?: number; readonly expected?: FileExpectation }): Promise<Record<string, unknown>> {
    if (!Number.isSafeInteger(options.length) || options.length < 0 || options.length > 128 * 1024 ** 3) throw new TypeError("stream length is invalid");
    const transfer = { id: identity("transfer"), path: [...createSandsurfGuestPath(path)], length: options.length, digest: digest(options.digest), mode: options.mode ?? 0o644, expected: options.expected ?? { kind: "any" } };
    await this.#operation({ kind: "begin-write", transfer }, "write-files", identity("begin"));
    try {
      let offset = 0;
      for await (const supplied of chunks) {
        if (!(supplied instanceof Uint8Array)) throw new TypeError("stream chunks must be Uint8Array values");
        for (let cursor = 0; cursor < supplied.byteLength; cursor += 64 * 1024) { const bytes = supplied.subarray(cursor, Math.min(cursor + 64 * 1024, supplied.byteLength)); await this.#operation({ kind: "write-chunk", transfer, offset, bytes: [...bytes] }, "write-files", identity("chunk")); offset += bytes.byteLength; }
      }
      if (offset !== options.length) throw new SandsurfHostError("transfer", "stream byte count does not match its declaration");
      return await this.#operation({ kind: "commit-write", transfer }, "write-files", identity("commit"));
    } catch (error) {
      try { await this.#operation({ kind: "abort-write", transfer }, "write-files", identity("abort")); } catch { /* The original exact failure remains authoritative. */ }
      throw error;
    }
  }
  async mkdir(path: string | Uint8Array, recursive = false): Promise<void> { await this.#operation({ kind: "mkdir", path: [...createSandsurfGuestPath(path)], recursive }, "write-files"); }
  async rename(from: string | Uint8Array, to: string | Uint8Array): Promise<void> { await this.#operation({ kind: "rename", from: [...createSandsurfGuestPath(from)], to: [...createSandsurfGuestPath(to)] }, "write-files"); }
  async remove(path: string | Uint8Array, recursive = false): Promise<void> { await this.#operation({ kind: "remove", path: [...createSandsurfGuestPath(path)], recursive }, "write-files"); }
  async chmod(path: string | Uint8Array, mode: number): Promise<void> { await this.#operation({ kind: "chmod", path: [...createSandsurfGuestPath(path)], mode }, "write-files"); }
  async readlink(path: string | Uint8Array): Promise<Uint8Array> { const response = await this.#operation({ kind: "readlink", path: [...createSandsurfGuestPath(path)] }, "read-files"); if (response.kind !== "link" || !Array.isArray(response.target)) throw protocol("readlink response"); return Uint8Array.from(response.target as number[]); }
  async symlink(path: string | Uint8Array, target: Uint8Array): Promise<void> { await this.#operation({ kind: "symlink", path: [...createSandsurfGuestPath(path)], target: [...target] }, "write-files"); }
  async watch(path: string | Uint8Array, recursive = false): Promise<FilesystemWatcher> {
    const machine = currentMachine(await this.#sandbox.inspect()); const watcherId = identity("watcher");
    await this.#operation({ kind: "watch", watcherId, epoch: machine.epoch, path: [...createSandsurfGuestPath(path)], recursive }, "read-files");
    return new FilesystemWatcher(this, watcherId, machine.epoch);
  }
  async pollWatcher(watcherId: string, epoch: number, maximum = 256): Promise<readonly Readonly<Record<string, unknown>>[]> { const response = await this.#operation({ kind: "poll-watch", watcherId, epoch, maximum }, "read-files"); if (response.kind !== "watch" || !Array.isArray(response.events)) throw protocol("watch response"); return response.events.map((event) => { if (!record(event)) throw protocol("watch event"); return event; }); }
  async closeWatcher(watcherId: string, epoch: number): Promise<void> { await this.#operation({ kind: "unwatch", watcherId, epoch }, "read-files"); }
  async #operation(request: Readonly<Record<string, unknown>>, capability: "read-files" | "write-files", operationId = identity("file")): Promise<Record<string, unknown>> {
    const operation = await this.#sandbox.workload({ kind: "filesystem", request }, capability, operationId); const mutation = operation.request;
    if (!record(mutation)) throw protocol("filesystem operation receipt");
    const response = await this.#sandbox.guest({ kind: "operation", operationId, requestDigest: text(mutation.requestDigest) }, capability);
    if (response.kind !== "file" || !record(response.response)) throw protocol("filesystem response"); return response.response;
  }
}

export class FilesystemWatcher {
  readonly id: string; readonly epoch: number; readonly #filesystem: SandboxFilesystem; #closed = false;
  constructor(filesystem: SandboxFilesystem, id: string, epoch: number) { this.#filesystem = filesystem; this.id = id; this.epoch = epoch; }
  poll(maximum = 256): Promise<readonly Readonly<Record<string, unknown>>[]> { if (this.#closed) throw new SandsurfHostError("client", "Filesystem watcher is closed"); return this.#filesystem.pollWatcher(this.id, this.epoch, maximum); }
  async close(): Promise<void> { if (!this.#closed) { await this.#filesystem.closeWatcher(this.id, this.epoch); this.#closed = true; } }
}

export class SandboxWorkspace {
  readonly #sandbox: Sandbox; readonly #fs: SandboxFilesystem; constructor(sandbox: Sandbox) { this.#sandbox = sandbox; this.#fs = sandbox.fs; }
  readFile(path: string | Uint8Array): Promise<Uint8Array> { return this.#fs.readFile(workspacePath(path)); }
  writeFile(path: string | Uint8Array, bytes: string | Uint8Array): Promise<Record<string, unknown>> { return this.#fs.writeFile(workspacePath(path), bytes); }
  async snapshot(options: { readonly attempts?: number } = {}): Promise<WorkspaceManifest> {
    const attempts = options.attempts ?? 3; if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > 10) throw new TypeError("snapshot attempts must be in 1..=10");
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const watcher = await this.#fs.watch("/workspace", true);
      try {
        const entries = await this.#snapshotEntries(); const events = await watcher.poll(4096);
        if (events.length === 0) return workspaceManifest(entries);
      } finally { await watcher.close(); }
    }
    throw new SandsurfHostError("conflict", "workspace did not remain stable during snapshot capture");
  }
  async diff(base: WorkspaceManifest): Promise<WorkspaceChangeSet> {
    validateWorkspaceManifest(base); const current = await this.snapshot();
    const previous = new Map(base.entries.map((entry) => [entry.path, entry])); const next = new Map(current.entries.map((entry) => [entry.path, entry]));
    const changes: WorkspaceChange[] = [];
    const removed = [...previous.keys()].filter((path) => !next.has(path)).sort((left, right) => pathDepth(right) - pathDepth(left) || Buffer.from(left).compare(Buffer.from(right)));
    for (const path of removed) changes.push({ kind: "delete", path });
    const upserts = current.entries.filter((entry) => { const old = previous.get(entry.path); return old === undefined || workspaceEntryDigest(old) !== workspaceEntryDigest(entry); });
    upserts.sort((left, right) => {
      if (left.kind === "directory" && right.kind !== "directory") return -1;
      if (left.kind !== "directory" && right.kind === "directory") return 1;
      return pathDepth(left.path) - pathDepth(right.path) || Buffer.from(left.path).compare(Buffer.from(right.path));
    });
    for (const entry of upserts) changes.push({ kind: "upsert", entry });
    return workspaceChangeSet(base, changes);
  }
  async exportToHost(options: WorkspaceExportOptions): Promise<WorkspaceApplyReport> {
    return this.applyToHost({ destination: options.destination, ...(options.operationId === undefined ? {} : { operationId: options.operationId }), changeSet: await this.diff(workspaceManifest([])) });
  }
  async applyToHost(options: WorkspaceApplyOptions): Promise<WorkspaceApplyReport> {
    if (!isAbsolute(options.destination)) throw new TypeError("host apply destination must be absolute"); validateWorkspaceChangeSet(options.changeSet);
    const destination = resolve(options.destination); const operationId = validateIdentity(options.operationId ?? identity("apply"));
    const approvalId = await this.#sandbox.approve({ kind: "host-apply", sandboxId: this.#sandbox.id, operationId, request: { destination, changeSetDigest: options.changeSet.digest } });
    const view = await this.#sandbox.inspect(); const scopeDigest = capabilityScope(this.#sandbox.id, "apply-to-host");
    for (const change of options.changeSet.changes) {
      if (change.kind !== "upsert" || change.entry.kind !== "file" || change.entry.digest === null) continue;
      const transfer = { id: identity("export"), length: change.entry.size, digest: change.entry.digest };
      await this.#sandbox.hostRequest({ kind: "begin-host-blob", sandboxId: this.#sandbox.id, expectedRevision: view.configurationRevision, scopeDigest, transfer, approvalId });
      let offset = 0;
      for await (const bytes of this.#readGuestFile(change.entry)) { await this.#sandbox.hostRequest({ kind: "write-host-blob", sandboxId: this.#sandbox.id, expectedRevision: view.configurationRevision, scopeDigest, transfer, offset, bytes: [...bytes] }); offset += bytes.byteLength; }
      if (offset !== change.entry.size) throw new SandsurfHostError("conflict", `workspace file ${change.entry.path} changed length during export`);
      await this.#sandbox.hostRequest({ kind: "commit-host-blob", sandboxId: this.#sandbox.id, expectedRevision: view.configurationRevision, scopeDigest, transfer });
    }
    const response = await this.#sandbox.hostRequest({ kind: "apply-host-workspace", sandboxId: this.#sandbox.id, operationId, expectedRevision: view.configurationRevision, scopeDigest, destination, changeSet: options.changeSet, approvalId });
    if (response.kind !== "host-apply" || !record(response.report)) throw protocol("host workspace apply response");
    return { operationId: text(response.report.operationId), changeSetDigest: digest(text(response.report.changeSetDigest)), applied: integer(response.report.applied), recovered: response.report.recovered === true };
  }
  async importFromHost(options: WorkspaceImportOptions): Promise<WorkspaceManifest> {
    if (!isAbsolute(options.source)) throw new TypeError("workspace import source must be absolute");
    const source = resolve(options.source); const operationId = validateIdentity(options.operationId ?? identity("import")); const exclusions = normalizeExclusions(options.exclusions ?? []); const maximumBytes = options.maximumBytes ?? 8 * 1024 ** 3;
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0 || maximumBytes > 128 * 1024 ** 3) throw new TypeError("workspace import maximumBytes is invalid");
    const approvalId = await this.#sandbox.approve({ kind: "host-import", sandboxId: this.#sandbox.id, operationId, request: { source, exclusions: [...exclusions].sort(), maximumBytes } });
    const view = await this.#sandbox.inspect();
    const captured = await this.#sandbox.hostRequest({ kind: "capture-host-tree", sandboxId: this.#sandbox.id, operationId, expectedRevision: view.configurationRevision, scopeDigest: capabilityScope(this.#sandbox.id, "write-files"), source, exclusions: [...exclusions].sort(), maximumBytes, approvalId });
    if (captured.kind !== "host-tree-capture" || !record(captured.capture)) throw protocol("host tree capture response");
    const capture = parseHostCapture(captured.capture); const entries: WorkspaceManifestEntry[] = [];
    let after = 0;
    for (;;) {
      const page = await this.#sandbox.hostRequest({ kind: "list-host-tree", sandboxId: this.#sandbox.id, operationId, after, maximum: 1024 });
      if (page.kind !== "host-tree-entries" || !record(page.capture) || !Array.isArray(page.entries)) throw protocol("host tree page response");
      const observed = parseHostCapture(page.capture); if (observed.manifestDigest !== capture.manifestDigest || observed.requestDigest !== capture.requestDigest) throw new SandsurfHostError("conflict", "host tree capture identity changed");
      for (const supplied of page.entries) entries.push(parseWorkspaceEntry(supplied));
      if (page.next === null) break; after = integer(page.next);
    }
    if (entries.length !== capture.entries) throw new SandsurfHostError("integrity", "host tree capture entry count changed");
    const manifest = workspaceManifest(entries); if (manifest.digest !== capture.manifestDigest) throw new SandsurfHostError("integrity", "host tree capture manifest digest changed");
    for (const entry of manifest.entries) if (entry.kind === "directory") await this.#fs.mkdir(workspacePath(entry.path), true);
    for (const entry of manifest.entries) {
      if (entry.kind === "directory") continue;
      if (entry.kind === "symlink") { if (entry.target === null) throw protocol("host symlink target"); await this.#fs.symlink(workspacePath(entry.path), Uint8Array.from(entry.target)); continue; }
      if (entry.digest === null) throw protocol("host file digest");
      await this.#fs.writeStream(workspacePath(entry.path), this.#captureBlob(operationId, entry.digest, entry.size), { length: entry.size, digest: entry.digest, mode: entry.mode, expected: { kind: "absent" } });
    }
    for (const entry of [...manifest.entries].reverse()) if (entry.kind === "directory") await this.#fs.chmod(workspacePath(entry.path), entry.mode);
    return manifest;
  }
  async *#captureBlob(operationId: string, expectedDigest: string, expectedLength: number): AsyncGenerator<Uint8Array, void, void> {
    let offset = 0;
    for (;;) {
      const response = await this.#sandbox.hostRequest({ kind: "read-host-tree-blob", sandboxId: this.#sandbox.id, operationId, digest: expectedDigest, offset, maximum: 64 * 1024 });
      if (response.kind !== "host-blob" || response.digest !== expectedDigest || integer(response.offset) !== offset || !Array.isArray(response.bytes) || typeof response.eof !== "boolean") throw protocol("host blob response");
      const bytes = Uint8Array.from(response.bytes as number[]); if (bytes.byteLength === 0 && response.eof !== true) throw protocol("empty non-terminal host blob page");
      offset += bytes.byteLength; yield bytes;
      if (response.eof === true) break;
    }
    if (offset !== expectedLength) throw new SandsurfHostError("integrity", "host blob length changed");
  }
  async #snapshotEntries(): Promise<WorkspaceManifestEntry[]> {
    const entries: WorkspaceManifestEntry[] = []; const collisions = new Set<string>();
    const visit = async (relative: string, absolute: Uint8Array): Promise<void> => {
      let after: Uint8Array | undefined;
      for (;;) {
        const response = await this.#fs.list(absolute, { ...(after === undefined ? {} : { after }), maximum: 1024 });
        if (response.kind !== "list" || !record(response.page) || !Array.isArray(response.page.entries)) throw protocol("workspace directory page");
        for (const supplied of response.page.entries) {
          if (!record(supplied) || !Array.isArray(supplied.name) || !record(supplied.stat)) throw protocol("workspace directory entry");
          const nameBytes = Uint8Array.from(supplied.name as number[]); const name = decodePortableName(nameBytes); const path = relative === "" ? name : `${relative}/${name}`; validatePortableWorkspacePath(path);
          const collision = path.toLocaleLowerCase("en-US"); if (collisions.has(collision)) throw new SandsurfHostError("conflict", "workspace contains a case-folding path collision"); collisions.add(collision);
          const guestPath = appendGuestPath(absolute, nameBytes); const stat = supplied.stat; const kind = text(stat.kind); const mode = integer(stat.mode); const size = integer(stat.size);
          if (kind === "directory") { entries.push({ path, kind: "directory", mode, size: 0, digest: null, target: null }); await visit(path, guestPath); }
          else if (kind === "symlink") { const target = await this.#fs.readlink(guestPath); entries.push({ path, kind: "symlink", mode, size: target.byteLength, digest: createHash("sha256").update(target).digest("hex"), target: [...target] }); }
          else if (kind === "regular") { const revision = await this.#fileRevision(guestPath); if (revision.size !== size) throw new SandsurfHostError("conflict", `workspace file ${path} changed during snapshot`); entries.push({ path, kind: "file", mode, size, digest: revision.digest, target: null }); }
          else throw new SandsurfHostError("unsupported", `workspace object ${path} is not portable`);
        }
        if (response.page.next === null) break; if (!Array.isArray(response.page.next)) throw protocol("workspace directory cursor"); after = Uint8Array.from(response.page.next as number[]);
      }
    };
    await visit("", Uint8Array.from(createSandsurfGuestPath("/workspace"))); return entries;
  }
  async #fileRevision(path: Uint8Array): Promise<{ readonly size: number; readonly digest: string }> {
    const response = await this.#fs.read(path, 0, 1); if (response.kind !== "read" || !record(response.range) || !record(response.range.revision)) throw protocol("workspace file revision");
    return { size: integer(response.range.revision.size), digest: digest(text(response.range.revision.digest)) };
  }
  async *#readGuestFile(entry: WorkspaceManifestEntry): AsyncGenerator<Uint8Array, void, void> {
    if (entry.digest === null) throw protocol("workspace file digest"); const path = workspacePath(entry.path); let offset = 0;
    for (;;) {
      const response = await this.#fs.read(path, offset, 64 * 1024); if (response.kind !== "read" || !record(response.range) || !record(response.range.revision) || !Array.isArray(response.range.bytes)) throw protocol("workspace file page");
      if (integer(response.range.offset) !== offset || integer(response.range.revision.size) !== entry.size || digest(text(response.range.revision.digest)) !== entry.digest) throw new SandsurfHostError("conflict", `workspace file ${entry.path} changed during export`);
      const bytes = Uint8Array.from(response.range.bytes as number[]); offset += bytes.byteLength; yield bytes;
      if (response.range.eof === true) break; if (bytes.byteLength === 0) throw protocol("empty non-terminal workspace file page");
    }
  }
}

export interface WorkspaceImportOptions { readonly source: string; readonly operationId?: string; readonly exclusions?: readonly string[]; readonly maximumBytes?: number; }
export interface WorkspaceManifestEntry { readonly path: string; readonly kind: "directory" | "file" | "symlink"; readonly mode: number; readonly size: number; readonly digest: string | null; readonly target: readonly number[] | null; }
export interface WorkspaceManifest { readonly digest: string; readonly entries: readonly WorkspaceManifestEntry[]; }
export type WorkspaceChange = { readonly kind: "upsert"; readonly entry: WorkspaceManifestEntry } | { readonly kind: "delete"; readonly path: string };
export interface WorkspaceChangeSet { readonly baseManifestDigest: string; readonly base: readonly WorkspaceManifestEntry[]; readonly changes: readonly WorkspaceChange[]; readonly digest: string; }
export interface WorkspaceExportOptions { readonly destination: string; readonly operationId?: string; }
export interface WorkspaceApplyOptions { readonly destination: string; readonly operationId?: string; readonly changeSet: WorkspaceChangeSet; }
export interface WorkspaceApplyReport { readonly operationId: string; readonly changeSetDigest: string; readonly applied: number; readonly recovered: boolean; }

function normalizeResources(value: ResourceEnvelope): Required<ResourceEnvelope> {
  const outputBytes = value.outputBytes ?? 1024 * 1024 * 1024; const processes = value.processes ?? 1024;
  for (const item of [value.vcpus, value.memoryMiB, value.diskBytes, outputBytes, processes]) if (!Number.isSafeInteger(item) || item <= 0) throw new TypeError("resource values must be positive safe integers");
  return { vcpus: value.vcpus, memoryMiB: value.memoryMiB, diskBytes: value.diskBytes, outputBytes, processes };
}
function sandboxViewFrom(response: Record<string, unknown>): SandboxInspection { if (response.kind === "lifecycle") { if (!record(response.operation) || typeof response.operation.delivery !== "string") throw protocol("lifecycle operation"); if (response.operation.delivery !== "applied") throw new SandsurfHostError(response.operation.delivery === "not-applied" ? "not-applied" : "ambiguous", `Lifecycle operation was ${response.operation.delivery}`); } const value = response.kind === "sandbox" ? response.value : response.kind === "lifecycle" ? response.sandbox : undefined; if (!record(value)) throw protocol("sandbox response"); return parseView(value); }
function parseView(value: unknown): SandboxInspection { if (!record(value) || !record(value.resources) || !record(value.runtimeConfiguration) || !record(value.lifecycleIntent) || !record(value.machine) || !record(value.workloadDefaults)) throw protocol("sandbox view"); return { ...value, runtimeConfiguration: parseRuntimeConfiguration(value.runtimeConfiguration) } as unknown as SandboxInspection; }
function currentMachine(view: SandboxInspection): { readonly epoch: number } { if (view.machine.kind !== "current" || !record(view.machine.value)) throw new SandsurfHostError("unavailable", "Sandbox machine observation is unavailable"); return { epoch: integer(view.machine.value.epoch) }; }
function parseProcess(value: unknown): ProcessInspection { if (!record(value) || !record(value.request) || !record(value.state) || (value.lineage !== null && !record(value.lineage))) throw protocol("process inspection"); return { request: value.request, guestPid: integer(value.guestPid), state: value.state, lineage: value.lineage }; }
function parseProcessObservation(value: unknown): ProcessObservation { if (!record(value) || (value.kind !== "current" && value.kind !== "unavailable")) throw protocol("process observation"); if (value.kind === "current") return { kind: "current", value: parseProcess(value.value) }; return { kind: "unavailable", lastKnown: value.lastKnown === null ? null : parseProcess(value.lastKnown) }; }
function parseEvidencePage(value: Record<string, unknown>): OutputPage { if (!Array.isArray(value.chunks)) throw protocol("output page"); const chunks = value.chunks as unknown[]; const after = integer(value.after); const cursor = integer(value.cursor); const available = integer(value.available); if (cursor < after || available < cursor) throw protocol("output page cursors"); return { after, available, chunks: chunks.map((chunk) => { if (!record(chunk) || !Array.isArray(chunk.bytes)) throw protocol("output chunk"); return { cursor: integer(chunk.offset), stream: text(chunk.stream) as OutputChunk["stream"], bytes: Uint8Array.from(chunk.bytes as number[]), digest: text(chunk.bytesDigest) }; }) }; }
function normalizeOutputRead(options: { readonly after?: number; readonly maximum?: number }): { readonly after: number; readonly maximum: number } { const after = options.after ?? 0; const maximum = options.maximum ?? 64 * 1024; if (!Number.isSafeInteger(after) || after < 0) throw new TypeError("output cursor must be a nonnegative safe integer"); if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 256 * 1024) throw new TypeError("output page size must be 1 through 256 KiB"); return { after, maximum }; }
function capabilityScope(sandboxId: string, capability: SandsurfCapability): string { return sandsurfDigest("grant", ["sandsurf-sandbox-capability-v1", sandboxId, capability]); }
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
function normalizeLiveResources(value: LiveResourceLimits): Readonly<Record<string, unknown>> { for (const item of [value.workloadMemoryBytes, value.workloadProcesses]) if (!Number.isSafeInteger(item) || item <= 0) throw new TypeError("live resource limit is invalid"); let cpuMax: readonly [number, number] | null = null; if (value.cpuMax !== undefined) { const [quota, period] = value.cpuMax; if (!Number.isSafeInteger(quota) || quota <= 0 || !Number.isSafeInteger(period) || period < 1000 || period > 1_000_000) throw new TypeError("CPU bandwidth limit is invalid"); cpuMax = [quota, period]; } return { workloadMemoryBytes: value.workloadMemoryBytes, workloadProcesses: value.workloadProcesses, cpuMax }; }
function parseRuntimeConfiguration(value: Record<string, unknown>): RuntimeConfiguration { if (!record(value.network) || !Array.isArray(value.network.rules) || !Array.isArray(value.exposures) || !record(value.resources)) throw protocol("runtime configuration"); return { network: normalizeNetworkPolicy(value.network as unknown as NetworkPolicy), exposures: value.exposures.map(parseExposure), resources: { workloadMemoryBytes: integer(value.resources.workloadMemoryBytes), workloadProcesses: integer(value.resources.workloadProcesses), ...(value.resources.cpuMax === null ? {} : { cpuMax: value.resources.cpuMax as unknown as readonly [number, number] }) } }; }
function parseExposure(value: unknown): Exposure { if (!record(value) || !record(value.spec)) throw protocol("exposure"); return { id: validateIdentity(text(value.id)), sandboxId: validateIdentity(text(value.sandboxId)), grantId: validateIdentity(text(value.grantId)), revision: integer(value.revision), spec: normalizeExposure({ guestAddress: text(value.spec.guestAddress), guestPort: integer(value.spec.guestPort), hostAddress: text(value.spec.hostAddress), hostPort: integer(value.spec.hostPort), public: value.spec.public === true }), active: value.active === true, boundPort: value.boundPort === null ? null : integer(value.boundPort) }; }
function parseSecret(value: Record<string, unknown>): SecretVersion { return { id: validateIdentity(text(value.id)), version: digest(text(value.version)), bytes: integer(value.bytes) }; }
function parseSecretRevocation(value: Record<string, unknown>): SecretRevocation {
  const evidence = value.evidence;
  if (!record(value.secret) || (evidence !== null && !record(evidence))) throw protocol("secret revocation evidence");
  const parsedEvidence = evidence === null ? null : {
    filesRemoved: integer(evidence.filesRemoved),
    environmentBindingsRemoved: integer(evidence.environmentBindingsRemoved),
    recipientsTerminated: identityList(evidence.recipientsTerminated),
    recipientsAlreadyStopped: identityList(evidence.recipientsAlreadyStopped),
    residualCopiesPossible: evidence.residualCopiesPossible === true,
    enforcementComplete: evidence.enforcementComplete === true,
  };
  return { operationId: validateIdentity(text(value.operationId)), sandboxId: validateIdentity(text(value.sandboxId)), secret: parseSecret(value.secret), terminateRecipients: value.terminateRecipients === true, enforced: parsedEvidence?.enforcementComplete === true, evidence: parsedEvidence };
}
function identityList(value: unknown): readonly string[] { if (!Array.isArray(value) || value.length > 1024) throw protocol("identity list"); return value.map((item) => validateIdentity(text(item))); }
function parseUsage(value: Record<string, unknown>): ResourceUsage { return { cpuMicros: integer(value.cpuMicros), memoryCurrent: integer(value.memoryCurrent), memoryPeak: integer(value.memoryPeak), diskLogicalBytes: integer(value.diskLogicalBytes), diskAllocatedBytes: integer(value.diskAllocatedBytes), ioReadBytes: integer(value.ioReadBytes), ioWriteBytes: integer(value.ioWriteBytes), outputRetainedBytes: integer(value.outputRetainedBytes), networkRxBytes: integer(value.networkRxBytes), networkTxBytes: integer(value.networkTxBytes), networkConnections: integer(value.networkConnections), processesCurrent: integer(value.processesCurrent), complete: value.complete === true, source: text(value.source), observedUnixMillis: integer(value.observedUnixMillis) }; }
function normalizeOciSource(options: ImageImportOptions): Readonly<Record<string, unknown>> {
  if (options.source !== undefined && options.reference !== undefined) throw new TypeError("Specify either source or reference for OCI import");
  const source = options.source ?? (options.reference === undefined ? undefined : { kind: "registry" as const, reference: options.reference });
  if (source === undefined) throw new TypeError("OCI import requires a source or registry reference");
  if (source.kind === "layout" || source.kind === "archive") {
    if (!source.path.startsWith("/")) throw new TypeError("OCI host paths must be absolute");
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
function parseCheckpoint(value: unknown): CheckpointInspection {
  if (!record(value) || !record(value.request) || !record(value.resources)) throw protocol("checkpoint record");
  const consistency = value.consistency === null ? null : text(value.consistency) as CheckpointConsistency;
  if (consistency !== null && !["crash", "filesystem", "application"].includes(consistency)) throw protocol("checkpoint consistency");
  const kind = text(value.request.kind) as CheckpointKind; if (kind !== "filesystem" && kind !== "full") throw protocol("checkpoint kind");
  const phase = text(value.phase) as CheckpointInspection["phase"]; if (!["admitted", "capturing", "ready"].includes(phase)) throw protocol("checkpoint phase");
  return { id: validateIdentity(text(value.request.id)), operationId: validateIdentity(text(value.request.operationId)), sandboxId: validateIdentity(text(value.request.sandboxId)), expectedEpoch: integer(value.request.expectedEpoch), expectedRevision: integer(value.request.expectedRevision), kind, parent: value.request.parent === null ? null : validateIdentity(text(value.request.parent)), requestDigest: digest(text(value.requestDigest)), phase, imageDigest: digest(text(value.imageDigest)), resources: normalizeResources(value.resources as unknown as ResourceEnvelope), consistency, workloadDiskDigest: value.workloadDiskDigest === null ? null : digest(text(value.workloadDiskDigest)), workloadDiskBytes: integer(value.workloadDiskBytes), manifestDigest: value.manifestDigest === null ? null : digest(text(value.manifestDigest)), sensitive: value.sensitive === true };
}
function parseReleaseStatus(value: Record<string, unknown>): ReleaseStatus { return { requestDigest: digest(text(value.requestDigest)), cleanupPending: value.cleanupPending === true }; }
function workspacePath(value: string | Uint8Array): Uint8Array {
  const relative = typeof value === "string" ? new TextEncoder().encode(value) : value;
  if (relative.byteLength === 0 || relative[0] === 0x2f) throw new TypeError("Workspace paths must be non-empty relative paths");
  const prefix = new TextEncoder().encode("/workspace/");
  const path = new Uint8Array(prefix.byteLength + relative.byteLength);
  path.set(prefix); path.set(relative, prefix.byteLength);
  return Uint8Array.from(createSandsurfGuestPath(path));
}
function normalizeExclusions(values: readonly string[]): ReadonlySet<string> {
  const result = new Set<string>();
  for (const value of values) {
    validatePortableWorkspacePath(value);
    result.add(value);
  }
  return result;
}
function workspaceManifest(entries: readonly WorkspaceManifestEntry[]): WorkspaceManifest {
  const ordered = [...entries].sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  const paths = new Set<string>(); for (const entry of ordered) { validateWorkspaceEntry(entry); if (paths.has(entry.path)) throw new TypeError("workspace manifest paths must be unique"); paths.add(entry.path); }
  const hash = createHash("sha256").update("SANDSURF-WORKSPACE-MANIFEST-V1\0");
  for (const entry of ordered) hash.update(Buffer.from(workspaceEntryDigest(entry), "hex"));
  return { digest: hash.digest("hex"), entries: ordered };
}
function workspaceEntryDigest(entry: WorkspaceManifestEntry): string { return sandsurfDigest("transfer", ["sandsurf-workspace-entry-v1", entry]); }
function workspaceChangeSet(base: WorkspaceManifest, changes: readonly WorkspaceChange[]): WorkspaceChangeSet {
  const hash = createHash("sha256").update("SANDSURF-WORKSPACE-CHANGES-V1\0");
  const paths = new Set<string>();
  for (const change of changes) { const path = change.kind === "upsert" ? change.entry.path : change.path; validatePortableWorkspacePath(path); if (change.kind === "upsert") validateWorkspaceEntry(change.entry); if (paths.has(path)) throw new TypeError("workspace change paths must be unique"); paths.add(path); hash.update(Buffer.from(sandsurfDigest("transfer", ["sandsurf-workspace-change-v1", change]), "hex")); }
  const changesDigest = hash.digest("hex"); return { baseManifestDigest: base.digest, base: base.entries, changes: [...changes], digest: sandsurfDigest("transfer", ["sandsurf-workspace-change-set-v1", base.digest, changesDigest]) };
}
function validateWorkspaceManifest(value: WorkspaceManifest): void { const rebuilt = workspaceManifest(value.entries); if (rebuilt.digest !== digest(value.digest)) throw new TypeError("workspace manifest digest mismatch"); }
function validateWorkspaceChangeSet(value: WorkspaceChangeSet): void { const base = { digest: value.baseManifestDigest, entries: value.base }; validateWorkspaceManifest(base); const rebuilt = workspaceChangeSet(base, value.changes); if (rebuilt.digest !== digest(value.digest)) throw new TypeError("workspace change-set digest mismatch"); }
function validateWorkspaceEntry(entry: WorkspaceManifestEntry): void {
  validatePortableWorkspacePath(entry.path); if (!Number.isSafeInteger(entry.mode) || entry.mode < 0 || entry.mode > 0o7777 || !Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > 128 * 1024 ** 3) throw new TypeError("workspace entry metadata is invalid");
  if (entry.kind === "directory") { if (entry.size !== 0 || entry.digest !== null || entry.target !== null) throw new TypeError("workspace directory entry is malformed"); return; }
  if (entry.kind === "file") { if (entry.digest === null || entry.target !== null) throw new TypeError("workspace file entry is malformed"); digest(entry.digest); return; }
  if (entry.kind !== "symlink" || entry.digest === null || entry.target === null || entry.target.length === 0 || entry.target.length > 4096 || entry.target.length !== entry.size || entry.target.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255) || createHash("sha256").update(Uint8Array.from(entry.target)).digest("hex") !== entry.digest) throw new TypeError("workspace symlink entry is malformed");
}
function validatePortableWorkspacePath(value: string): void {
  if (value.length === 0 || value.startsWith("/") || value.endsWith("/") || value.includes("\\") || value.includes("\0") || value.normalize("NFC") !== value || value.split("/").some((part) => part.length === 0 || part === "." || part === ".." || windowsReserved(part))) throw new TypeError("workspace paths must be normalized portable relative paths");
}
function windowsReserved(value: string): boolean { const stem = (value.split(".")[0] ?? value).toUpperCase(); return value.endsWith(" ") || value.endsWith(".") || value.includes(":") || ["CON", "PRN", "AUX", "NUL"].includes(stem) || /^(?:COM|LPT)[1-9]$/u.test(stem); }
function decodePortableName(value: Uint8Array): string { try { return new TextDecoder("utf-8", { fatal: true }).decode(value); } catch { throw new SandsurfHostError("unsupported", "workspace contains a non-UTF-8 path that cannot be exported to every host"); } }
function appendGuestPath(parent: Uint8Array, name: Uint8Array): Uint8Array { if (name.byteLength === 0 || name.includes(0) || name.includes(0x2f)) throw protocol("workspace entry name"); const value = new Uint8Array(parent.byteLength + 1 + name.byteLength); value.set(parent); value[parent.byteLength] = 0x2f; value.set(name, parent.byteLength + 1); return Uint8Array.from(createSandsurfGuestPath(value)); }
function pathDepth(path: string): number { return path.split("/").length; }
function parseWorkspaceEntry(value: unknown): WorkspaceManifestEntry {
  if (!record(value) || typeof value.path !== "string" || !["directory", "file", "symlink"].includes(String(value.kind))) throw protocol("host tree entry");
  const target = value.target === null ? null : Array.isArray(value.target) && value.target.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255) ? value.target as number[] : (() => { throw protocol("host tree link target"); })();
  return { path: value.path, kind: value.kind as WorkspaceManifestEntry["kind"], mode: integer(value.mode), size: integer(value.size), digest: value.digest === null ? null : digest(text(value.digest)), target };
}
function parseHostCapture(value: Record<string, unknown>): { readonly requestDigest: string; readonly manifestDigest: string; readonly entries: number; readonly bytes: number } {
  return { requestDigest: digest(text(value.requestDigest)), manifestDigest: digest(text(value.manifestDigest)), entries: integer(value.entries), bytes: integer(value.bytes) };
}
function identity(prefix: string): string { return `${prefix}-${randomUUID()}`; }
function validateIdentity(value: string): string { if (!/^[A-Za-z0-9_-]{1,128}$/u.test(value)) throw new TypeError("Sandsurf identity is malformed"); return value; }
function digest(value: string): string { if (!/^[a-f0-9]{64}$/u.test(value)) throw new TypeError("Sandsurf digest is malformed"); return value; }
function protocol(subject: string): SandsurfHostError { return new SandsurfHostError("protocol", `native host returned an invalid ${subject}`); }
