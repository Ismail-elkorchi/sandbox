import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { NativeHostClient, SandsurfHostError, integer, record, text } from "./native-host.js";
import { createSandsurfGuestPath, sandsurfDigest } from "./sandsurf-protocol.js";

export type SandsurfCapability = "spawn" | "read-files" | "write-files" | "workload-admin" | "network" | "expose-port" | "deliver-secret" | "apply-to-host" | "increase-resources" | "checkpoint" | "fork" | "release-evidence";
export type DesiredSandboxState = "running" | "paused" | "stopped" | "suspended" | "destroyed";
export interface AuthorityChange { readonly kind: "sandbox-create" | "lifecycle" | "grant"; readonly sandboxId: string; readonly operationId: string; readonly request: Readonly<Record<string, unknown>>; }
export type AuthorityDecision = boolean | { readonly approvalId: string };
export type SandsurfAuthorizer = (change: AuthorityChange) => AuthorityDecision | Promise<AuthorityDecision>;
export interface SandsurfOpenOptions { readonly directory: string; readonly authorizer?: SandsurfAuthorizer; }
export interface ResourceEnvelope { readonly vcpus: number; readonly memoryMiB: number; readonly diskBytes: number; readonly outputBytes?: number; readonly processes?: number; }
export interface SandboxCreateOptions { readonly id?: string; readonly operationId?: string; readonly image: string; readonly resources: ResourceEnvelope; readonly capabilities?: Partial<Record<SandsurfCapability, boolean>>; }
export type Qualification = { readonly kind: "qualified"; readonly evidence: string } | { readonly kind: "unqualified"; readonly reasons: readonly string[] };
export interface HostInspection { readonly hostId: string; readonly platform: string; readonly architecture: string; readonly guestArchitecture: string; readonly engine: "firecracker" | "apple-virtualization" | "hyper-v"; readonly lifecycle: Qualification; readonly fullState: Qualification; }
export interface SandboxInspection { readonly id: string; readonly imageDigest: string; readonly resources: Required<ResourceEnvelope>; readonly configurationRevision: number; readonly reservation: "held" | "released"; readonly lifecycleIntent: Readonly<Record<string, unknown>>; readonly machine: Readonly<Record<string, unknown>>; }

export class Sandsurf {
  readonly sandboxes: SandboxCollection;
  readonly #client: NativeHostClient;
  readonly #authorizer: SandsurfAuthorizer | undefined;
  #closed = false;
  private constructor(client: NativeHostClient, authorizer: SandsurfAuthorizer | undefined) { this.#client = client; this.#authorizer = authorizer; this.sandboxes = new SandboxCollection(this); }
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
  readonly #host: Sandsurf;
  #view: SandboxInspection;
  constructor(host: Sandsurf, view: SandboxInspection) { this.#host = host; this.#view = view; this.id = view.id; this.processes = new ProcessCollection(this); this.fs = new SandboxFilesystem(this); this.workspace = new SandboxWorkspace(this.fs); }
  get revision(): number { return this.#view.configurationRevision; }
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
  async #lifecycle(desired: DesiredSandboxState, operationId: string): Promise<SandboxInspection> {
    validateIdentity(operationId); const approvalId = await this.#host.approve({ kind: "lifecycle", sandboxId: this.id, operationId, request: { desired, expectedRevision: this.revision } });
    this.#view = sandboxViewFrom(await this.#host.request({ kind: "lifecycle", sandboxId: this.id, operationId, expectedRevision: this.revision, desired, approvalId })); return this.#view;
  }
}

export interface TerminalSize { readonly columns: number; readonly rows: number; readonly pixelWidth?: number; readonly pixelHeight?: number; }
export interface SpawnOptions { readonly operationId?: string; readonly processId?: string; readonly argv: readonly string[]; readonly cwd?: string; readonly environment?: Readonly<Record<string, string>>; readonly user?: string; readonly stdio?: "pipes" | "terminal"; readonly terminalSize?: TerminalSize; readonly lifetime?: "job" | "sandbox"; readonly outputBytes?: number; }
export interface ProcessInspection { readonly request: Readonly<Record<string, unknown>>; readonly guestPid: number; readonly state: Readonly<Record<string, unknown>>; }

export class ProcessCollection {
  readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox) { this.#sandbox = sandbox; }
  async spawn(options: SpawnOptions): Promise<SandboxProcess> {
    const operationId = validateIdentity(options.operationId ?? identity("spawn")); const processId = validateIdentity(options.processId ?? identity("process"));
    const machine = currentMachine(await this.#sandbox.inspect()); const stdio = options.stdio ?? "pipes";
    const terminalSize = stdio === "terminal" ? { columns: options.terminalSize?.columns ?? 80, rows: options.terminalSize?.rows ?? 24, pixelWidth: options.terminalSize?.pixelWidth ?? 0, pixelHeight: options.terminalSize?.pixelHeight ?? 0 } : null;
    await this.#sandbox.workload({ kind: "spawn", request: { sandboxId: this.#sandbox.id, epoch: machine.epoch, processId, operationId, argv: [...options.argv], cwd: options.cwd ?? "/workspace", environment: { ...(options.environment ?? {}) }, user: options.user ?? null, stdio, terminalSize, lifetime: options.lifetime ?? "job", outputBytes: options.outputBytes ?? 64 * 1024 * 1024 } }, options.user === "root" || options.user === "0" ? "workload-admin" : "spawn", operationId);
    return new SandboxProcess(this.#sandbox, processId);
  }
  async get(id: string): Promise<SandboxProcess> { const process = new SandboxProcess(this.#sandbox, validateIdentity(id)); await process.inspect(); return process; }
  async list(): Promise<readonly ProcessInspection[]> {
    const response = await this.#sandbox.guest({ kind: "processes" }, "spawn");
    if (response.kind !== "processes" || !Array.isArray(response.processes)) throw protocol("process list response");
    return response.processes.map(parseProcess);
  }
}

export interface OutputChunk { readonly cursor: number; readonly stream: "stdout" | "stderr" | "terminal"; readonly bytes: Uint8Array; readonly digest: string; }
export interface OutputPage { readonly after: number; readonly available: number; readonly chunks: readonly OutputChunk[]; readonly requiredBytes?: number; }

export class SandboxProcess {
  readonly id: string; readonly #sandbox: Sandbox;
  constructor(sandbox: Sandbox, id: string) { this.#sandbox = sandbox; this.id = id; }
  async inspect(): Promise<ProcessInspection> { const response = await this.#sandbox.guest({ kind: "process", processId: this.id }, "spawn"); if (response.kind !== "process" || !record(response.process)) throw protocol("process response"); return parseProcess(response.process); }
  async wait(options: { readonly pollMs?: number; readonly signal?: AbortSignal } = {}): Promise<ProcessInspection> { for (;;) { if (options.signal?.aborted === true) throw options.signal.reason; const value = await this.inspect(); if (value.state.kind !== "running") return value; await new Promise((done) => setTimeout(done, options.pollMs ?? 50)); } }
  async readOutput(options: { readonly after?: number; readonly maximum?: number } = {}): Promise<OutputPage> {
    const response = await this.#sandbox.guest({ kind: "read-output", processId: this.id, after: options.after ?? 0, maximum: options.maximum ?? 64 * 1024 }, "spawn");
    if (response.kind !== "output" || !record(response.page) || !Array.isArray(response.page.chunks)) throw protocol("output response");
    return { after: integer(response.page.after), available: integer(response.page.available), chunks: response.page.chunks.map((chunk) => { if (!record(chunk) || !Array.isArray(chunk.bytes)) throw protocol("output chunk"); return { cursor: integer(chunk.cursor), stream: text(chunk.stream) as OutputChunk["stream"], bytes: Uint8Array.from(chunk.bytes as number[]), digest: text(chunk.digest) }; }), ...(response.page.requiredBytes === null ? {} : { requiredBytes: integer(response.page.requiredBytes) }) };
  }
  async write(bytes: Uint8Array, operationId = identity("input")): Promise<void> { await this.#sandbox.workload({ kind: "write-input", processId: this.id, bytes: [...bytes] }, "spawn", operationId); }
  async closeInput(operationId = identity("close")): Promise<void> { await this.#sandbox.workload({ kind: "close-input", processId: this.id }, "spawn", operationId); }
  async signal(signal: number, group = true, operationId = identity("signal")): Promise<void> { await this.#sandbox.workload({ kind: "signal", processId: this.id, signal, group }, "spawn", operationId); }
  async terminate(graceMillis = 1000, operationId = identity("terminate")): Promise<void> { await this.#sandbox.workload({ kind: "terminate", processId: this.id, graceMillis }, "spawn", operationId); }
  async resize(size: TerminalSize, operationId = identity("resize")): Promise<void> { await this.#sandbox.workload({ kind: "resize-terminal", processId: this.id, size: { columns: size.columns, rows: size.rows, pixelWidth: size.pixelWidth ?? 0, pixelHeight: size.pixelHeight ?? 0 } }, "spawn", operationId); }
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
  readFile(path: string | Uint8Array): Promise<Uint8Array> { return this.#fs.readFile(path); }
  writeFile(path: string | Uint8Array, bytes: string | Uint8Array): Promise<Record<string, unknown>> { return this.#fs.writeFile(path, bytes); }
}

function normalizeResources(value: ResourceEnvelope): Required<ResourceEnvelope> {
  const outputBytes = value.outputBytes ?? 1024 * 1024 * 1024; const processes = value.processes ?? 1024;
  for (const item of [value.vcpus, value.memoryMiB, value.diskBytes, outputBytes, processes]) if (!Number.isSafeInteger(item) || item <= 0) throw new TypeError("resource values must be positive safe integers");
  return { vcpus: value.vcpus, memoryMiB: value.memoryMiB, diskBytes: value.diskBytes, outputBytes, processes };
}
function sandboxViewFrom(response: Record<string, unknown>): SandboxInspection { const value = response.kind === "sandbox" ? response.value : response.kind === "lifecycle" ? response.sandbox : undefined; if (!record(value)) throw protocol("sandbox response"); return parseView(value); }
function parseView(value: unknown): SandboxInspection { if (!record(value) || !record(value.resources) || !record(value.lifecycleIntent) || !record(value.machine)) throw protocol("sandbox view"); return value as unknown as SandboxInspection; }
function currentMachine(view: SandboxInspection): { readonly epoch: number } { if (view.machine.kind !== "current" || !record(view.machine.value)) throw new SandsurfHostError("unavailable", "Sandbox machine observation is unavailable"); return { epoch: integer(view.machine.value.epoch) }; }
function parseProcess(value: unknown): ProcessInspection { if (!record(value) || !record(value.request) || !record(value.state)) throw protocol("process inspection"); return { request: value.request, guestPid: integer(value.guestPid), state: value.state }; }
function capabilityScope(sandboxId: string, capability: SandsurfCapability): string { return sandsurfDigest("grant", ["sandsurf-sandbox-capability-v1", sandboxId, capability]); }
function identity(prefix: string): string { return `${prefix}-${randomUUID()}`; }
function validateIdentity(value: string): string { if (!/^[A-Za-z0-9_-]{1,128}$/u.test(value)) throw new TypeError("Sandsurf identity is malformed"); return value; }
function digest(value: string): string { if (!/^[a-f0-9]{64}$/u.test(value)) throw new TypeError("Sandsurf digest is malformed"); return value; }
function protocol(subject: string): SandsurfHostError { return new SandsurfHostError("protocol", `native host returned an invalid ${subject}`); }
