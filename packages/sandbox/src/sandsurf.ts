import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { NativeHostClient, SandsurfHostError, integer, record, text } from "./native-host.js";
import { createSandsurfGuestPath, sandsurfDigest } from "./sandsurf-protocol.js";

export type SandsurfCapability = "spawn" | "read-files" | "write-files" | "workload-admin" | "network" | "expose-port" | "deliver-secret" | "apply-to-host" | "increase-resources" | "checkpoint" | "fork" | "release-evidence";
export type DesiredSandboxState = "running" | "paused" | "stopped" | "suspended" | "destroyed";
export interface AuthorityChange { readonly kind: "sandbox-create" | "lifecycle" | "grant" | "image-import" | "evidence-loss"; readonly sandboxId: string; readonly operationId: string; readonly request: Readonly<Record<string, unknown>>; }
export type AuthorityDecision = boolean | { readonly approvalId: string };
export type SandsurfAuthorizer = (change: AuthorityChange) => AuthorityDecision | Promise<AuthorityDecision>;
export interface SandsurfOpenOptions { readonly directory: string; readonly authorizer?: SandsurfAuthorizer; }
export interface ResourceEnvelope { readonly vcpus: number; readonly memoryMiB: number; readonly diskBytes: number; readonly outputBytes?: number; readonly processes?: number; }
export interface SandboxCreateOptions { readonly id?: string; readonly operationId?: string; readonly image: string; readonly resources: ResourceEnvelope; readonly capabilities?: Partial<Record<SandsurfCapability, boolean>>; }
export type Qualification = { readonly kind: "qualified"; readonly evidence: string } | { readonly kind: "unqualified"; readonly reasons: readonly string[] };
export interface HostInspection { readonly hostId: string; readonly platform: string; readonly architecture: string; readonly guestArchitecture: string; readonly guestPlatform: string; readonly engine: "firecracker" | "apple-virtualization" | "hyper-v"; readonly lifecycle: Qualification; readonly fullState: Qualification; readonly images: Qualification; }
export interface WorkloadDefaults { readonly environment: Readonly<Record<string, string>>; readonly user: string | null; readonly workingDirectory: string | null; readonly entrypoint: readonly string[]; readonly command: readonly string[]; }
export interface SandboxInspection { readonly id: string; readonly imageDigest: string; readonly resources: Required<ResourceEnvelope>; readonly configurationRevision: number; readonly reservation: "held" | "released"; readonly lifecycleIntent: Readonly<Record<string, unknown>>; readonly machine: Readonly<Record<string, unknown>>; readonly workloadDefaults: WorkloadDefaults; }
export type OciImageSource = { readonly kind: "layout"; readonly path: string } | { readonly kind: "archive"; readonly path: string } | { readonly kind: "registry"; readonly reference: string; readonly credential?: string };
export interface ImageImportOptions { readonly source?: OciImageSource; readonly reference?: string; readonly platform?: string; readonly operationId?: string; }
export interface ImageInspection { readonly digest: string; readonly sourceDigest: string; readonly platform: string; readonly architecture: string; readonly logicalBytes: number; readonly provenanceDigest: string; }
export interface Receipt { readonly sandboxId: string; readonly epoch: number; readonly processId: string; readonly operationId: string; readonly requestDigest: string; readonly outcome: Readonly<Record<string, unknown>>; readonly output: Readonly<Record<string, unknown>>; readonly cleanupDigest: string; readonly accountingDigest: string; }
export interface ReceiptView { readonly receipt: Receipt; readonly digest: string; }
export interface CaptureCommitment { readonly storeId: string; readonly commitmentId: string; readonly manifestDigest: string; readonly receiptDigest: string; readonly output: Readonly<Record<string, unknown>>; }
export type ReleaseDisposition = { readonly kind: "complete-capture"; readonly commitment: CaptureCommitment } | { readonly kind: "continuing-retention"; readonly pin: string } | { readonly kind: "authorized-loss"; readonly authorization?: string };
export interface ReleaseStatus { readonly requestDigest: string; readonly cleanupPending: boolean; }

export class Sandsurf {
  readonly sandboxes: SandboxCollection;
  readonly images: ImageCollection;
  readonly #client: NativeHostClient;
  readonly #authorizer: SandsurfAuthorizer | undefined;
  #closed = false;
  private constructor(client: NativeHostClient, authorizer: SandsurfAuthorizer | undefined) { this.#client = client; this.#authorizer = authorizer; this.sandboxes = new SandboxCollection(this); this.images = new ImageCollection(this); }
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
}

export class SandsurfImage {
  readonly id: string;
  readonly inspection: ImageInspection;
  constructor(inspection: ImageInspection) { this.id = inspection.digest; this.inspection = inspection; }
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
  readonly fs: SandboxFilesystem;
  readonly workspace: SandboxWorkspace;
  readonly operations: SandboxOperations;
  readonly #host: Sandsurf;
  #view: SandboxInspection;
  constructor(host: Sandsurf, view: SandboxInspection) { this.#host = host; this.#view = view; this.id = view.id; this.processes = new ProcessCollection(this); this.fs = new SandboxFilesystem(this); this.workspace = new SandboxWorkspace(this.fs); this.operations = new SandboxOperations(this); }
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
    const scopeDigest = options.scopeDigest ?? capabilityScope(this.id, capability); const operationId = validateIdentity(options.operationId ?? identity("grant"));
    const approvalId = await this.#host.approve({ kind: "grant", sandboxId: this.id, operationId, request: { capability, scopeDigest, expectedRevision: this.revision } });
    const response = await this.#host.request({ kind: "set-grant", sandboxId: this.id, grantId: identity("grant"), expectedRevision: this.revision, capability, scopeDigest, revoked: false, approvalId });
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
    validateIdentity(operationId); const approvalId = await this.#host.approve({ kind: "lifecycle", sandboxId: this.id, operationId, request: { desired, expectedRevision: this.revision } });
    this.#view = sandboxViewFrom(await this.#host.request({ kind: "lifecycle", sandboxId: this.id, operationId, expectedRevision: this.revision, desired, approvalId })); return this.#view;
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

export interface TerminalSize { readonly columns: number; readonly rows: number; readonly pixelWidth?: number; readonly pixelHeight?: number; }
export interface SpawnOptions { readonly operationId?: string; readonly processId?: string; readonly argv: readonly string[]; readonly cwd?: string; readonly environment?: Readonly<Record<string, string>>; readonly user?: string; readonly stdio?: "pipes" | "terminal"; readonly terminalSize?: TerminalSize; readonly lifetime?: "job" | "sandbox"; readonly outputBytes?: number; }
export interface ProcessInspection { readonly request: Readonly<Record<string, unknown>>; readonly guestPid: number; readonly state: Readonly<Record<string, unknown>>; }
export type ProcessObservation = { readonly kind: "current"; readonly value: ProcessInspection } | { readonly kind: "unavailable"; readonly lastKnown: ProcessInspection | null };

export class ProcessCollection {
  readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox) { this.#sandbox = sandbox; }
  async spawn(options: SpawnOptions): Promise<SandboxProcess> {
    const operationId = validateIdentity(options.operationId ?? identity("spawn")); const processId = validateIdentity(options.processId ?? identity("process"));
    const view = await this.#sandbox.inspect(); const machine = currentMachine(view); const stdio = options.stdio ?? "pipes";
    const terminalSize = stdio === "terminal" ? { columns: options.terminalSize?.columns ?? 80, rows: options.terminalSize?.rows ?? 24, pixelWidth: options.terminalSize?.pixelWidth ?? 0, pixelHeight: options.terminalSize?.pixelHeight ?? 0 } : null;
    const user = options.user ?? view.workloadDefaults.user ?? "root";
    const operation = await this.#sandbox.workload({ kind: "spawn", request: { sandboxId: this.#sandbox.id, epoch: machine.epoch, processId, operationId, argv: [...options.argv], cwd: options.cwd ?? view.workloadDefaults.workingDirectory ?? "/workspace", environment: { ...view.workloadDefaults.environment, ...(options.environment ?? {}) }, user, stdio, terminalSize, lifetime: options.lifetime ?? "job", outputBytes: options.outputBytes ?? 64 * 1024 * 1024 } }, user === "root" || user === "0" || user.startsWith("0:") ? "workload-admin" : "spawn", operationId);
    if (operation.delivery === "not-applied") throw new SandsurfHostError("workload", `Process ${processId} was not applied`);
    return new SandboxProcess(this.#sandbox, processId);
  }
  async get(id: string): Promise<SandboxProcess> { const process = new SandboxProcess(this.#sandbox, validateIdentity(id)); await process.inspect(); return process; }
  async list(): Promise<readonly ProcessObservation[]> {
    const response = await this.#sandbox.hostRequest({ kind: "list-processes", sandboxId: this.#sandbox.id });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "processes" || !Array.isArray(response.response.processes)) throw protocol("process list response");
    return response.response.processes.map(parseProcessObservation);
  }
}

export interface OutputChunk { readonly cursor: number; readonly stream: "stdout" | "stderr" | "terminal"; readonly bytes: Uint8Array; readonly digest: string; }
export interface OutputPage { readonly after: number; readonly available: number; readonly chunks: readonly OutputChunk[]; readonly requiredBytes?: number; }

export class SandboxProcess {
  readonly id: string; readonly output: ProcessOutput; readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox, id: string) { this.#sandbox = sandbox; this.id = id; this.output = new ProcessOutput(this); }
  async inspect(): Promise<ProcessObservation> { const response = await this.#sandbox.hostRequest({ kind: "get-process", sandboxId: this.#sandbox.id, processId: this.id }); if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "process") throw protocol("process response"); if (response.response.process === null) throw new SandsurfHostError("missing", `Process ${this.id} does not exist`); return parseProcessObservation(response.response.process); }
  async wait(options: { readonly pollMs?: number; readonly signal?: AbortSignal } = {}): Promise<ProcessInspection> { for (;;) { if (options.signal?.aborted === true) throw options.signal.reason; const observed = await this.inspect(); if (observed.kind !== "current") throw new SandsurfHostError("unavailable", `Process ${this.id} is not currently observable`); if (observed.value.state.kind !== "running") return observed.value; await new Promise((done) => setTimeout(done, options.pollMs ?? 50)); } }
  async readOutput(options: { readonly after?: number; readonly maximum?: number } = {}): Promise<OutputPage> {
    const response = await this.#sandbox.hostRequest({ kind: "read-evidence", sandboxId: this.#sandbox.id, processId: this.id, after: options.after ?? 0, maximum: options.maximum ?? 64 * 1024 });
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
  async write(bytes: Uint8Array, operationId = identity("input")): Promise<void> { await this.#sandbox.workload({ kind: "write-input", processId: this.id, bytes: [...bytes] }, "spawn", operationId); }
  async closeInput(operationId = identity("close")): Promise<void> { await this.#sandbox.workload({ kind: "close-input", processId: this.id }, "spawn", operationId); }
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
    const response = await this.#sandbox.hostRequest({ kind: "read-pinned-evidence", sandboxId: this.#sandbox.id, pinId: this.id, after: options.after ?? 0, maximum: options.maximum ?? 64 * 1024 });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "output" || !record(response.response.page)) throw protocol("pinned output response");
    return parseEvidencePage(response.response.page);
  }
}

export type FileExpectation = { readonly kind: "any" } | { readonly kind: "absent" } | { readonly kind: "matches"; readonly size: number; readonly digest: string };
export class SandboxFilesystem {
  readonly #sandbox: Sandbox; constructor(sandbox: Sandbox) { this.#sandbox = sandbox; }
  stat(path: string | Uint8Array, follow = true): Promise<Record<string, unknown>> { return this.#operation({ kind: "stat", path: [...createSandsurfGuestPath(path)], follow }, "read-files"); }
  list(path: string | Uint8Array, options: { readonly after?: Uint8Array; readonly maximum?: number } = {}): Promise<Record<string, unknown>> { return this.#operation({ kind: "list", path: [...createSandsurfGuestPath(path)], after: options.after === undefined ? null : [...options.after], maximum: options.maximum ?? 256 }, "read-files"); }
  read(path: string | Uint8Array, offset = 0, maximum = 64 * 1024): Promise<Record<string, unknown>> { return this.#operation({ kind: "read", path: [...createSandsurfGuestPath(path)], offset, maximum }, "read-files"); }
  async readFile(path: string | Uint8Array): Promise<Uint8Array> {
    const guestPath = createSandsurfGuestPath(path); const chunks: Uint8Array[] = []; let offset = 0;
    for (;;) { const response = await this.read(Uint8Array.from(guestPath), offset); if (response.kind !== "read" || !record(response.range) || !Array.isArray(response.range.bytes)) throw protocol("file range response"); const bytes = Uint8Array.from(response.range.bytes as number[]); chunks.push(bytes); offset += bytes.byteLength; if (response.range.eof === true) break; }
    const result = new Uint8Array(offset); let cursor = 0; for (const chunk of chunks) { result.set(chunk, cursor); cursor += chunk.byteLength; } return result;
  }
  writeFile(path: string | Uint8Array, bytes: string | Uint8Array, options: { readonly mode?: number; readonly expected?: FileExpectation } = {}): Promise<Record<string, unknown>> { const value = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes; return this.#operation({ kind: "write", path: [...createSandsurfGuestPath(path)], bytes: [...value], mode: options.mode ?? 0o644, expected: options.expected ?? { kind: "any" } }, "write-files"); }
  async mkdir(path: string | Uint8Array, recursive = false): Promise<void> { await this.#operation({ kind: "mkdir", path: [...createSandsurfGuestPath(path)], recursive }, "write-files"); }
  async rename(from: string | Uint8Array, to: string | Uint8Array): Promise<void> { await this.#operation({ kind: "rename", from: [...createSandsurfGuestPath(from)], to: [...createSandsurfGuestPath(to)] }, "write-files"); }
  async remove(path: string | Uint8Array, recursive = false): Promise<void> { await this.#operation({ kind: "remove", path: [...createSandsurfGuestPath(path)], recursive }, "write-files"); }
  async chmod(path: string | Uint8Array, mode: number): Promise<void> { await this.#operation({ kind: "chmod", path: [...createSandsurfGuestPath(path)], mode }, "write-files"); }
  async readlink(path: string | Uint8Array): Promise<Uint8Array> { const response = await this.#operation({ kind: "readlink", path: [...createSandsurfGuestPath(path)] }, "read-files"); if (response.kind !== "link" || !Array.isArray(response.target)) throw protocol("readlink response"); return Uint8Array.from(response.target as number[]); }
  async symlink(path: string | Uint8Array, target: Uint8Array): Promise<void> { await this.#operation({ kind: "symlink", path: [...createSandsurfGuestPath(path)], target: [...target] }, "write-files"); }
  async #operation(request: Readonly<Record<string, unknown>>, capability: "read-files" | "write-files"): Promise<Record<string, unknown>> {
    const operationId = identity("file"); const operation = await this.#sandbox.workload({ kind: "filesystem", request }, capability, operationId); const mutation = operation.request;
    if (!record(mutation)) throw protocol("filesystem operation receipt");
    const response = await this.#sandbox.guest({ kind: "operation", operationId, requestDigest: text(mutation.requestDigest) }, capability);
    if (response.kind !== "file" || !record(response.response)) throw protocol("filesystem response"); return response.response;
  }
}

export class SandboxWorkspace {
  readonly #fs: SandboxFilesystem; constructor(fs: SandboxFilesystem) { this.#fs = fs; }
  readFile(path: string | Uint8Array): Promise<Uint8Array> { return this.#fs.readFile(workspacePath(path)); }
  writeFile(path: string | Uint8Array, bytes: string | Uint8Array): Promise<Record<string, unknown>> { return this.#fs.writeFile(workspacePath(path), bytes); }
}

function normalizeResources(value: ResourceEnvelope): Required<ResourceEnvelope> {
  const outputBytes = value.outputBytes ?? 1024 * 1024 * 1024; const processes = value.processes ?? 1024;
  for (const item of [value.vcpus, value.memoryMiB, value.diskBytes, outputBytes, processes]) if (!Number.isSafeInteger(item) || item <= 0) throw new TypeError("resource values must be positive safe integers");
  return { vcpus: value.vcpus, memoryMiB: value.memoryMiB, diskBytes: value.diskBytes, outputBytes, processes };
}
function sandboxViewFrom(response: Record<string, unknown>): SandboxInspection { const value = response.kind === "sandbox" ? response.value : response.kind === "lifecycle" ? response.sandbox : undefined; if (!record(value)) throw protocol("sandbox response"); return parseView(value); }
function parseView(value: unknown): SandboxInspection { if (!record(value) || !record(value.resources) || !record(value.lifecycleIntent) || !record(value.machine) || !record(value.workloadDefaults)) throw protocol("sandbox view"); return value as unknown as SandboxInspection; }
function currentMachine(view: SandboxInspection): { readonly epoch: number } { if (view.machine.kind !== "current" || !record(view.machine.value)) throw new SandsurfHostError("unavailable", "Sandbox machine observation is unavailable"); return { epoch: integer(view.machine.value.epoch) }; }
function parseProcess(value: unknown): ProcessInspection { if (!record(value) || !record(value.request) || !record(value.state)) throw protocol("process inspection"); return { request: value.request, guestPid: integer(value.guestPid), state: value.state }; }
function parseProcessObservation(value: unknown): ProcessObservation { if (!record(value) || (value.kind !== "current" && value.kind !== "unavailable")) throw protocol("process observation"); if (value.kind === "current") return { kind: "current", value: parseProcess(value.value) }; return { kind: "unavailable", lastKnown: value.lastKnown === null ? null : parseProcess(value.lastKnown) }; }
function parseEvidencePage(value: Record<string, unknown>): OutputPage { if (!Array.isArray(value.chunks)) throw protocol("output page"); const chunks = value.chunks as unknown[]; return { after: integer(value.cursor), available: integer(value.available), chunks: chunks.map((chunk) => { if (!record(chunk) || !Array.isArray(chunk.bytes)) throw protocol("output chunk"); return { cursor: integer(chunk.offset), stream: text(chunk.stream) as OutputChunk["stream"], bytes: Uint8Array.from(chunk.bytes as number[]), digest: text(chunk.bytesDigest) }; }) }; }
function capabilityScope(sandboxId: string, capability: SandsurfCapability): string { return sandsurfDigest("grant", ["sandsurf-sandbox-capability-v1", sandboxId, capability]); }
function normalizeOciSource(options: ImageImportOptions): Readonly<Record<string, unknown>> {
  if (options.source !== undefined && options.reference !== undefined) throw new TypeError("Specify either source or reference for OCI import");
  const source = options.source ?? (options.reference === undefined ? undefined : { kind: "registry" as const, reference: options.reference });
  if (source === undefined) throw new TypeError("OCI import requires a source or registry reference");
  if (source.kind === "layout" || source.kind === "archive") {
    if (!source.path.startsWith("/")) throw new TypeError("OCI host paths must be absolute");
    return { kind: source.kind, path: resolve(source.path) };
  }
  if (source.reference.length === 0 || source.reference.length > 4096) throw new TypeError("OCI registry reference is malformed");
  return { kind: "registry", reference: source.reference, credential: source.credential ?? null };
}
function parseImage(value: unknown): ImageInspection {
  if (!record(value)) throw protocol("image record");
  return { digest: digest(text(value.digest)), sourceDigest: digest(text(value.sourceDigest)), platform: text(value.platform), architecture: text(value.architecture), logicalBytes: integer(value.logicalBytes), provenanceDigest: digest(text(value.provenanceDigest)) };
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
function identity(prefix: string): string { return `${prefix}-${randomUUID()}`; }
function validateIdentity(value: string): string { if (!/^[A-Za-z0-9_-]{1,128}$/u.test(value)) throw new TypeError("Sandsurf identity is malformed"); return value; }
function digest(value: string): string { if (!/^[a-f0-9]{64}$/u.test(value)) throw new TypeError("Sandsurf digest is malformed"); return value; }
function protocol(subject: string): SandsurfHostError { return new SandsurfHostError("protocol", `native host returned an invalid ${subject}`); }
