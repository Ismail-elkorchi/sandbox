import { MachineArtifacts } from "./artifacts.js";
import type { AuthorityChange, ConsolePage, DerivedImagePublishOptions, DesiredMachineState, ExecOptions, ExecResult, ExecShellOptions, MachineCreateOptions, MachineEvent, MachineEventPage, MachineEventValue, MachineForkOptions, MachineGenerationPrecondition, MachineInspection, MachineLifecycleOptions, MachineRevisionPrecondition, ShellOptions, SnapshotCreateOptions, SnapshotInspection } from "./contracts.js";
import { ExecutionCollection, OutputSegment, TerminalCollection } from "./executions.js";
import type { Terminal } from "./executions.js";
import { MachineFilesystem } from "./guest-files.js";
import { Image } from "./images.js";
import { integer, record, SandsurfHostError, text } from "./native-host.js";
import { MachineNetwork, MachinePorts } from "./network.js";
import { currentMachine, expectedCounter, machineViewFrom, nativeObservationOrder, normalizeEventRead, normalizeExecutionDefaults, normalizeLifetime, normalizeResources, parseImage, parseMachineEventValue, parseOperationRecord, parseSnapshot, parseView, resolveGenerationPrecondition, resolveMachinePreconditions, resolveRevisionPrecondition, runtimeResponse } from "./observations.js";
import { Operation } from "./operations.js";
import { MachineResources } from "./resources.js";
import { sandsurfDigest } from "./sandsurf-protocol.js";
import type { Sandsurf } from "./sandsurf.js";
import { authorize, digest, dispatchGuest, identity, observe, observed, protocol, queryGuest, subscribe, subscribeConsole, transport, validateIdentity } from "./sdk-internal.js";
import { MachineSecrets } from "./secrets.js";

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
  async fork(options: MachineForkOptions): Promise<Machine> {
    if (this.inspection.phase !== "ready" || this.inspection.kind !== "disk") throw new SandsurfHostError("conflict", "Only a ready disk snapshot can be forked");
    const machineId = validateIdentity(options.id); const operationId = validateIdentity(options.operationId ?? identity("fork")); const resources = normalizeResources(options.resources ?? this.inspection.resources);
    const lifetime = normalizeLifetime(options.lifetime);
    const approvalId = await this.#host[authorize]({ kind: "fork", machineId, operationId, request: { snapshotId: this.id, sourceMachineId: this.inspection.machineId, resources, lifetime } });
    const response = await this.#host[transport]({ kind: "fork-machine", machineId, snapshotId: this.id, resources, lifetime, operationId, approvalId });
    const machine = new Machine(this.#host, machineViewFrom(response, machineId));
    return machine;
  }
  async publishImage(options: DerivedImagePublishOptions = {}): Promise<Image> {
    if (this.inspection.phase !== "ready" || this.inspection.kind !== "disk") throw new SandsurfHostError("conflict", "Only a ready disk snapshot can be published");
    const operationId = validateIdentity(options.operationId ?? identity("publish-image"));
    const allowSensitive = options.allowSensitive ?? false;
    const approvalId = await this.#host[authorize]({ kind: "image-publish", machineId: this.inspection.machineId, operationId, request: { snapshotId: this.id, allowSensitive } });
    const response = await this.#host[transport]({ kind: "publish-snapshot-image", snapshotId: this.id, allowSensitive, operationId, approvalId });
    if (response.kind !== "image-import" || !record(response.operation) || response.operation.phase !== "published" || !record(response.operation.image)) throw protocol("derived image response");
    return new Image(parseImage(response.operation.image));
  }
  /** Retire snapshot bytes, not output archives or execution history. Native
   * full-state readers can leave cleanup pending until their VMM detaches. */
  async release(options: { readonly operationId?: string } = {}): Promise<Operation> {
    const operationId = validateIdentity(options.operationId ?? identity("release-snapshot"));
    const approvalId = await this.#host[authorize]({ kind: "snapshot-release", machineId: this.inspection.machineId, operationId, request: { snapshotId: this.id } });
    const response = await this.#host[transport]({ kind: "release-snapshot", snapshotId: this.id, operationId, approvalId });
    if (response.kind !== "snapshot-release" || !record(response.operation)) throw protocol("snapshot release response");
    const observation = parseOperationRecord({ kind: "snapshot-release", value: response.operation }, operationId, this.inspection.machineId, "host-authority");
    if (observation.observation.kind !== "snapshot-release" || observation.observation.snapshotId !== this.id || observation.requestDigest !== sandsurfDigest("snapshot", ["sandsurf-release-snapshot-v1", operationId, this.id])) throw protocol("snapshot release identity");
    return new Operation(this.#host, observation);
  }
}

export class MachineCollection {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async create(options: MachineCreateOptions): Promise<Machine> {
    const machineId = validateIdentity(options.id);
    const operationId = validateIdentity(options.operationId ?? identity("create"));
    digest(options.image); const resources = normalizeResources(options.resources);
    const lifetime = normalizeLifetime(options.lifetime);
    const executionDefaults = normalizeExecutionDefaults(options);
    const approvalId = await this.#host[authorize]({ kind: "machine-create", machineId, operationId, request: { image: options.image, resources, executionDefaults, network: { rules: [] }, lifetime } });
    const response = await this.#host[transport]({ kind: "create-machine", machineId, imageDigest: options.image, resources, executionDefaults, lifetime, operationId, approvalId });
    const machine = new Machine(this.#host, machineViewFrom(response, machineId));
    return machine;
  }
  async connect(id: string): Promise<Machine> {
    const machineId = validateIdentity(id);
    return new Machine(this.#host, machineViewFrom(await this.#host[transport]({ kind: "get-machine", machineId }), machineId));
  }
  async list(options: { readonly after?: string; readonly maximum?: number } = {}): Promise<readonly Machine[]> {
    const response = await this.#host[transport]({ kind: "list-machines", after: options.after ?? null, maximum: options.maximum ?? 100 });
    if (response.kind !== "machines" || !Array.isArray(response.values)) throw protocol("machine list response");
    return response.values.map((value) => new Machine(this.#host, parseView(value)));
  }
}

export class Machine {
  readonly console = new MachineConsole(this);
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
  outputSegment(segmentId: string): OutputSegment { return new OutputSegment(this, validateIdentity(segmentId)); }
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
  [subscribe](after: number, maximum: number, signal?: AbortSignal): AsyncGenerator<Record<string, unknown>, void> { return this.#host[subscribe](this.id, after, maximum, signal); }
  [subscribeConsole](generation: number, after: number, maximum: number, signal?: AbortSignal): AsyncGenerator<Record<string, unknown>, void> { return this.#host[subscribeConsole](this.id, generation, after, maximum, signal); }
  async [authorize](change: AuthorityChange): Promise<string> { return this.#host[authorize](change); }
  async #lifecycle(desired: DesiredMachineState, options: MachineLifecycleOptions): Promise<MachineInspection> {
    const operationId = validateIdentity(options.operationId ?? identity(desired)); const expectedRevision = await resolveRevisionPrecondition(this, options.expectedRevision); const approvalId = await this.#host[authorize]({ kind: "lifecycle", machineId: this.id, operationId, request: { desired, expectedRevision } });
    const response = await this.#host[transport]({ kind: "lifecycle", machineId: this.id, operationId, expectedRevision, desired, approvalId });
    if (response.kind === "lifecycle") this[observe](parseView(response.machine));
    return machineViewFrom(response);
  }
}

export class MachineConsole {
  readonly #machine: Machine;
  constructor(machine: Machine) { this.#machine = machine; }
  /** A fresh attachment binds a generation. Supplying a generation permits
   * historical reads; writes still require the current native generation. */
  async attach(options: { readonly generation?: number } = {}): Promise<NativeConsole> {
    const generation = expectedCounter(options.generation, "console generation") ?? currentMachine(await this.#machine.inspect()).generation;
    const attachment = new NativeConsole(this.#machine, generation);
    await attachment.read({ maximum: 1 });
    return attachment;
  }
}

export class NativeConsole {
  readonly generation: number;
  readonly #machine: Machine;
  #detached = false;
  readonly #detach = new AbortController();
  constructor(machine: Machine, generation: number) {
    this.#machine = machine; this.generation = expectedCounter(generation, "console generation")!;
  }
  /** Detach only this SDK handle. The VM and guardian capture continue. */
  detach(): void { this.#detached = true; this.#detach.abort(new SandsurfHostError("detached", "Native console handle is detached")); }
  async read(options: { readonly after?: number; readonly maximum?: number } = {}): Promise<ConsolePage> {
    this.#attached();
    const after = integer(options.after ?? 0); const maximum = integer(options.maximum ?? 64 * 1024);
    if (maximum < 1 || maximum > 64 * 1024) throw new RangeError("console page must be 1..65536 bytes");
    const response = runtimeResponse(await this.#machine[transport]({ kind: "read-console", machineId: this.#machine.id, generation: this.generation, after, maximum }));
    return this.#page(response, after, maximum);
  }
  #page(response: Readonly<Record<string, unknown>>, after: number, maximum: number): ConsolePage {
    if (response.kind !== "console" || !record(response.page)) throw protocol("native console response");
    const page = response.page;
    const cursor = integer(page.cursor); const available = integer(page.available);
    if (page.generation !== this.generation || page.after !== after || !(page.bytes instanceof Uint8Array) ||
        page.bytes.byteLength > maximum || cursor < after || cursor > available ||
        typeof page.open !== "boolean" || typeof page.captureFailed !== "boolean") throw protocol("native console page");
    const end = after + page.bytes.byteLength;
    const loss = page.loss === null ? null : record(page.loss) ? { from: integer(page.loss.from), to: integer(page.loss.to) } : undefined;
    if (loss === undefined || (loss === null ? end !== cursor : loss.from !== end || loss.to !== cursor || loss.from >= loss.to)) throw protocol("native console loss coverage");
    return { generation: this.generation, after, cursor, available, bytes: page.bytes, loss, open: page.open, captureFailed: page.captureFailed };
  }
  /** Returns the accepted prefix only. Delivery uncertainty is surfaced by the
   * transport; input is never automatically retried. */
  async write(bytes: Uint8Array): Promise<number> {
    this.#attached();
    if (!(bytes instanceof Uint8Array) || bytes.byteLength < 1 || bytes.byteLength > 4096) throw new RangeError("console input must be 1..4096 bytes");
    const response = runtimeResponse(await this.#machine[transport]({ kind: "write-console", machineId: this.#machine.id, generation: this.generation, bytes }));
    if (response.kind !== "console-input") throw protocol("native console input response");
    const accepted = integer(response.accepted);
    if (accepted > bytes.byteLength) throw protocol("native console accepted prefix");
    return accepted;
  }
  /** Follow credit-driven durable pages. Each generation reserves a 512 KiB prefix;
   * excess output advances the cursor with explicit loss. The guardian admits
   * 64 archived generations, 1 MiB/s of reads and 32 KiB/s of input per computer. */
  async *follow(options: { readonly after?: number; readonly maximum?: number; readonly signal?: AbortSignal } = {}): AsyncGenerator<ConsolePage, void> {
    this.#attached();
    let after = integer(options.after ?? 0);
    const maximum = integer(options.maximum ?? 64 * 1024);
    if (maximum < 1 || maximum > 64 * 1024) throw new RangeError("console page must be 1..65536 bytes");
    const signal = options.signal === undefined ? this.#detach.signal : AbortSignal.any([options.signal, this.#detach.signal]);
    for await (const response of this.#machine[subscribeConsole](this.generation, after, maximum, signal)) {
      const page = this.#page(runtimeResponse(response), after, maximum);
      if (page.bytes.byteLength !== 0 || page.loss !== null || !page.open || page.captureFailed) yield page;
      after = page.cursor;
      if ((!page.open || page.captureFailed) && after === page.available) return;
    }
  }
  #attached(): void { if (this.#detached) throw new SandsurfHostError("detached", "Native console handle is detached"); }
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
  async rollback(snapshotId: string, options: MachineRevisionPrecondition & { readonly operationId?: string } = {}): Promise<Operation> {
    const id = validateIdentity(snapshotId); const operationId = validateIdentity(options.operationId ?? identity("rollback")); const expectedRevision = await resolveRevisionPrecondition(this.#machine, options.expectedRevision);
    const approvalId = await this.#machine[authorize]({ kind: "snapshot", machineId: this.#machine.id, operationId, request: { action: "rollback", snapshotId: id, expectedRevision } });
    const response = await this.#machine[transport]({ kind: "rollback-filesystem", machineId: this.#machine.id, snapshotId: id, operationId, expectedRevision, approvalId });
    if (response.kind !== "rollback" || !record(response.value)) throw protocol("rollback response");
    const observation = parseOperationRecord({ kind: "rollback", value: response.value }, operationId, this.#machine.id, "host-authority");
    if (observation.observation.kind !== "rollback" || observation.observation.snapshotId !== id || observation.observation.expectedRevision !== expectedRevision) throw protocol("rollback admission identity");
    return new Operation(this.#host, observation, this.#machine.id);
  }
}

export class MachineEvents {
  readonly #machine: Machine;
  constructor(machine: Machine) { this.#machine = machine; }
  async read(options: { readonly after?: number; readonly maximum?: number } = {}): Promise<MachineEventPage> {
    const { after, maximum } = normalizeEventRead(options);
    const response = await this.#machine[transport]({ kind: "list-events", machineId: this.#machine.id, after, maximum });
    return this.#page(response, after, maximum);
  }
  #page(response: Readonly<Record<string, unknown>>, after: number, maximum: number): MachineEventPage {
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "events" || !record(response.response.page) || !Array.isArray(response.response.page.events)) throw protocol("event page response");
    const page = response.response.page; const events = page.events;
    if (!Array.isArray(events)) throw protocol("runtime events");
    const cursor = integer(page.cursor); const available = integer(page.available);
    let expected = after;
    const parsed = events.map((event: unknown) => {
        if (!record(event) || !record(event.value)) throw protocol("runtime event");
        const eventCursor = integer(event.cursor); const eventDigest = text(event.digest);
        let expectedDigest: string;
        try { expectedDigest = sandsurfDigest("operation", ["sandsurf-runtime-event-v1", this.#machine.id, eventCursor, event.value]); }
        catch { throw protocol("runtime event digest input"); }
        if (eventCursor !== ++expected || eventDigest !== expectedDigest) throw protocol("runtime event coverage or digest");
        let value: MachineEventValue;
        try { value = parseMachineEventValue(event.value, this.#machine.id); }
        catch { throw protocol("runtime event observation"); }
        return Object.freeze({ cursor: eventCursor, value: Object.freeze(value), digest: eventDigest });
    });
    if (events.length > maximum || expected !== cursor || cursor > available) throw protocol("runtime event page boundary");
    return Object.freeze({ cursor, available, events: Object.freeze(parsed) });
  }
  async *follow(options: { readonly after?: number; readonly maximum?: number; readonly signal?: AbortSignal } = {}): AsyncGenerator<MachineEvent, void> {
    let { after, maximum } = normalizeEventRead(options);
    for await (const response of this.#machine[subscribe](after, maximum, options.signal)) {
      const page = this.#page(response, after, maximum);
      for (const event of page.events) { yield event; }
      after = page.cursor;
    }
  }
}
