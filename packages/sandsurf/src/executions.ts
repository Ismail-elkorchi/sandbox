import type { ExecOptions, ExecResult, ExecShellOptions, ExecutionOperationOptions, ExecutionSignalOptions, ExecutionStatus, ExecutionTerminateOptions, MachineGenerationPrecondition, NativeMachineObservation, OutputChunk, OutputPage, OutputSegmentInspection, ReceiptView, ReleaseDisposition, ReleaseStatus, ShellOptions, SpawnOptions, TerminalOpenOptions, TerminalSize } from "./contracts.js";
import { parseExecutionReceipt, parseExecutionRequest } from "./execution.js";
import type { ExecutionInspection } from "./execution.js";
import type { Machine } from "./machines.js";
import { integer, record, SandsurfHostError } from "./native-host.js";
import { currentMachine, expectedCounter, nativeBoundaryAffects, normalizeOutputRead, parseEvidencePage, parseExecutionStatus, parseOutputSegmentResponse, parseReleaseStatus, runtimeEventBelongsToProcess } from "./observations.js";
import { sandsurfDigest, validateSandsurfOutputBoundary } from "./sandsurf-protocol.js";
import type { OutputBoundary } from "./sandsurf-protocol.js";
import { authorize, childIdentity, digest, dispatchGuest, executionFence, identity, observed, protocol, transport, validateIdentity } from "./sdk-internal.js";

export class ExecutionInterruptedError extends SandsurfHostError {
  readonly executionId: string; readonly generation: number; readonly observation: NativeMachineObservation;
  constructor(execution: Execution, observation: NativeMachineObservation) {
    super("execution-interrupted", `Execution ${execution.id} generation ${execution.generation} was interrupted by native ${observation.state}; this is not a guest exit or a complete output capture`);
    this.name = "ExecutionInterruptedError";
    this.executionId = execution.id; this.generation = execution.generation; this.observation = observation;
  }
}

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
    const outputBudget = integer(view.runtimeConfiguration.resources.outputBytes);
    const outputBytes = options.outputBytes ?? Math.max(1, Math.min(16 * 1024 * 1024, Math.floor(outputBudget / 8)));
    if (!Number.isSafeInteger(outputBytes) || outputBytes < 1 || outputBytes > outputBudget) throw new TypeError("process output reservation must fit the Machine output budget");
    await this.#machine[dispatchGuest]({ kind: "spawn", request: { machineId: this.#machine.id, generation: authority.expectedGeneration, executionId, operationId, argv: [...options.argv], cwd: options.cwd ?? view.executionDefaults.workingDirectory ?? "/", environment: { ...view.executionDefaults.environment, ...(options.environment ?? {}) }, user, stdio, terminalSize, activeDeadlineMillis, elapsedDeadlineUnixMillis, outputBytes } }, operationId, authority);
    return new Execution(this.#machine, executionId, authority.expectedGeneration);
  }
  async exec(options: ExecOptions): Promise<ExecResult> {
    const { signal, ...spawn } = options;
    const process = await this.start(spawn);
    return { process, inspection: await process.waitLeader({ ...(signal === undefined ? {} : { signal }) }) };
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
    const request = parseExecutionRequest(response.response.request);
    if (request.executionId !== executionId || request.machineId !== this.#machine.id) throw protocol("execution reservation identity");
    const status = parseExecutionStatus(response.response.process, this.#machine.id);
    if (status.executionId !== executionId) throw protocol("execution reservation identity");
    return new Execution(this.#machine, executionId, status.generation);
  }
  async list(): Promise<readonly ExecutionStatus[]> {
    const response = await this.#machine[transport]({ kind: "list-processes", machineId: this.#machine.id });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "processes" || !Array.isArray(response.response.processes)) throw protocol("process list response");
    return response.response.processes.map((value: unknown) => parseExecutionStatus(value, this.#machine.id));
  }
}

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
    const request = parseExecutionRequest(response.response.request);
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
  inspect(): Promise<ExecutionStatus> { this.#requireAttached(); return this.process.inspect(); }
  waitLeader(options: { readonly signal?: AbortSignal } = {}): Promise<ExecutionInspection> { this.#requireAttached(); return this.process.waitLeader(options); }
  waitCapture(options: { readonly signal?: AbortSignal } = {}): Promise<ExecutionInspection> { this.#requireAttached(); return this.process.waitCapture(options); }
  resize(size: TerminalSize, options: ExecutionOperationOptions = {}): Promise<void> { this.#requireAttached(); return this.process.resize(size, options); }
  signal(signal: number, options: ExecutionSignalOptions = {}): Promise<void> { this.#requireAttached(); return this.process.signal(signal, options); }
  terminate(options: ExecutionTerminateOptions = {}): Promise<void> { this.#requireAttached(); return this.process.terminate(options); }
  #requireAttached(): void { if (!this.#attached) throw new SandsurfHostError("client", `Terminal ${this.id} is detached`); }
}

const executionMachines = new WeakMap<Execution, Machine>();

export class Execution {
  readonly id: string; readonly generation: number; readonly input: ExecutionInput; readonly output: ExecutionOutput; readonly #machine: Machine;
  constructor(machine: Machine, id: string, generation: number) { this.#machine = machine; this.id = id; this.generation = expectedCounter(generation, "execution generation")!; executionMachines.set(this, machine); this.input = new ExecutionInput(this); this.output = new ExecutionOutput(this, machine); }
  [executionFence](options: ExecutionOperationOptions): ExecutionOperationOptions {
    if (options.expectedGeneration !== undefined && options.expectedGeneration !== this.generation) throw new SandsurfHostError("stale-generation", "An execution handle cannot be rebound to another generation");
    return { ...options, expectedGeneration: this.generation };
  }
  async inspect(): Promise<ExecutionStatus> {
    const response = await this.#machine[transport]({ kind: "get-process", machineId: this.#machine.id, executionId: this.id });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "process") throw protocol("process response");
    const status = parseExecutionStatus(response.response.process, this.#machine.id);
    if (status.executionId !== this.id || status.generation !== this.generation) throw protocol("execution status identity");
    return status;
  }
  waitLeader(options: { readonly signal?: AbortSignal } = {}): Promise<ExecutionInspection> { return this.#wait("leader", options); }
  waitCapture(options: { readonly signal?: AbortSignal } = {}): Promise<ExecutionInspection> { return this.#wait("capture", options); }
  async #wait(boundaryKind: "leader" | "capture", options: { readonly signal?: AbortSignal }): Promise<ExecutionInspection> {
    if (options.signal?.aborted === true) throw options.signal.reason;
    const boundary = await this.#machine.events.read({ maximum: 1 });
    const status = await this.inspect();
    let terminal: ExecutionInspection | undefined;
    const complete = async (value: ExecutionInspection): Promise<boolean> => {
      if (value.state.kind === "running" || (boundaryKind === "capture" && value.state.kind === "draining")) return false;
      if (boundaryKind === "leader" || value.state.kind === "unknown") return true;
      if (value.state.kind !== "exited") throw protocol("execution capture state");
      terminal = value;
      const receipt = await this.receipt();
      if (receipt === undefined) return false;
      if (receipt.receipt.executionId !== this.id || receipt.receipt.generation !== this.generation ||
          sandsurfDigest("receipt", [receipt.receipt.outcome, receipt.receipt.output, receipt.receipt.cleanupDigest, receipt.receipt.accountingDigest]) !==
          sandsurfDigest("receipt", [value.state.outcome, value.state.output, value.state.cleanupDigest, value.state.accountingDigest])) throw protocol("capture receipt disagrees with completed process");
      return true;
    };
    const reported = status.report.kind === "current" ? status.report.value : status.report.lastKnown;
    if (reported !== null && reported.request.generation === this.generation &&
        (status.report.kind === "current" || reported.state.kind !== "running") && await complete(reported)) return reported;
    requireExecutionContinuity(this, status);
    for await (const event of this.#machine.events.follow({ after: boundary.available, ...(options.signal === undefined ? {} : { signal: options.signal }) })) {
      if (boundaryKind === "capture" && terminal !== undefined && event.value.kind === "receipt" && event.value.executionId === this.id && await complete(terminal)) return terminal;
      if (event.value.kind === "machine" && nativeBoundaryAffects(event.value.observation, this.generation)) {
        const latest = await this.inspect();
        const reported = latest.report.kind === "current" ? latest.report.value : latest.report.lastKnown;
        if (reported !== null && reported.request.generation === this.generation && reported.state.kind !== "running" && await complete(reported)) return reported;
        requireExecutionContinuity(this, latest);
      }
      if (event.value.kind !== "execution") continue;
      const process = event.value.execution;
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
    const receiptDigest = digest(response.response.digest);
    const receipt = parseExecutionReceipt(response.response.receipt, receiptDigest);
    if (receipt.machineId !== this.#machine.id || receipt.executionId !== this.id || receipt.generation !== this.generation) throw protocol("receipt identity");
    return { receipt, digest: receiptDigest };
  }
  async acknowledge(receiptDigest: string, options: { readonly operationId?: string } = {}): Promise<void> { await this.#evidenceCommand("acknowledge-receipt", { receiptDigest: digest(receiptDigest) }, validateIdentity(options.operationId ?? identity("acknowledge"))); }
  async release(receipt: ReceiptView, disposition: ReleaseDisposition, options: { readonly operationId?: string } = {}): Promise<ReleaseStatus> {
    const operationId = validateIdentity(options.operationId ?? identity("release-evidence"));
    let lossApprovalId: string | null = null; let normalized: Readonly<Record<string, unknown>>;
    if (disposition.kind === "complete-capture") normalized = { kind: disposition.kind, commitment: disposition.commitment };
    else if (disposition.kind === "continuing-retention") normalized = { kind: disposition.kind, segment: validateIdentity(disposition.segment) };
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
  async #evidenceCommand(kind: "acknowledge-receipt", fields: Readonly<Record<string, unknown>>, operationId: string): Promise<void> {
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
  /** Seal an exact captured prefix, or the current host boundary on first admission.
   * Retrying the same operation never expands its original capture. No guest
   * completion, receipt, live management channel or machine revision is required.
   */
  async seal(segmentId: string, options: { readonly operationId?: string; readonly boundary?: OutputBoundary } = {}): Promise<OutputSegment> {
    const id = validateIdentity(segmentId);
    if (options.boundary !== undefined) validateSandsurfOutputBoundary(options.boundary);
    const response = await this.#machine[transport]({ kind: "seal-output", machineId: this.#machine.id,
      executionId: this.#process.id, generation: this.#process.generation, segmentId: id, expected: options.boundary ?? null,
      operationId: validateIdentity(options.operationId ?? identity("seal-output")) });
    const segment = parseOutputSegmentResponse(response);
    if (segment.id !== id || segment.executionId !== this.#process.id || segment.machineId !== this.#machine.id || segment.generation !== this.#process.generation) throw protocol("sealed output identity");
    return new OutputSegment(this.#machine, id);
  }
  async read(options: { readonly after?: number; readonly maximum?: number } = {}): Promise<OutputPage> { const { after, maximum } = normalizeOutputRead(options); const response = await this.#machine[transport]({ kind: "read-evidence", machineId: this.#machine.id, executionId: this.#process.id, after, maximum }); if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "output" || !record(response.response.page) || !Array.isArray(response.response.page.chunks)) throw protocol("output response"); return parseEvidencePage(response.response.page); }
  async *follow(options: { readonly after?: number; readonly maximum?: number; readonly signal?: AbortSignal } = {}): AsyncGenerator<OutputChunk, void, void> {
    let cursor = options.after ?? 0;
    const boundary = await this.#machine.events.read({ maximum: 1 });
    const events = this.#machine.events.follow({ after: boundary.available, ...(options.signal === undefined ? {} : { signal: options.signal }) });
    try {
      for (;;) {
        if (options.signal?.aborted === true) throw options.signal.reason;
        const page = await this.read({ after: cursor, ...(options.maximum === undefined ? {} : { maximum: options.maximum }) });
        for (const chunk of page.chunks) { cursor = chunk.cursor + chunk.bytes.byteLength; yield chunk; }
        const receipt = await this.#process.receipt();
        if (receipt !== undefined && cursor >= integer(receipt.receipt.output.finalCursor)) return;
        if (cursor < page.available || page.chunks.length > 0) continue;
        requireExecutionContinuity(this.#process, await this.#process.inspect());
        for (;;) {
          const event = await events.next();
          if (event.done) throw new SandsurfHostError("unavailable", `Process ${this.#process.id} event stream ended`);
          if (runtimeEventBelongsToProcess(event.value, this.#process.id)) break;
        }
      }
    } finally {
      await events.return();
    }
  }
}

export class OutputSegment {
  readonly id: string; readonly #machine: Machine;
  constructor(machine: Machine, id: string) { this.#machine = machine; this.id = id; }
  async inspect(): Promise<OutputSegmentInspection> {
    const segment = parseOutputSegmentResponse(await this.#machine[transport]({ kind: "get-output-segment", machineId: this.#machine.id, segmentId: this.id }));
    if (segment.id !== this.id) throw protocol("output segment identity");
    return segment;
  }
  async read(options: { readonly after?: number; readonly maximum?: number } = {}): Promise<OutputPage> {
    const { after, maximum } = normalizeOutputRead(options);
    const response = await this.#machine[transport]({ kind: "read-output-segment", machineId: this.#machine.id, segmentId: this.id, after, maximum });
    if (response.kind !== "runtime" || !record(response.response) || response.response.kind !== "output" || !record(response.response.page)) throw protocol("output segment response");
    return parseEvidencePage(response.response.page);
  }
}

function requireExecutionContinuity(execution: Execution, status: ExecutionStatus): void {
  if (status.executionId !== execution.id) throw protocol("execution status identity");
  if (status.generation !== execution.generation) throw protocol("immutable execution incarnation changed generation");
  if (status.interruption !== null) throw new ExecutionInterruptedError(execution, status.interruption);
}
