import type { ArtifactInspection, Capability, CpuLedgers, ChangeSet, ConfigurationDeliveryObservation, DesiredMachineState, ExecutionObservation, ExecutionStatus, Exposure, ExposureSpec, ImageDefaults, ImageImportOptions, ImageInspection, MachineCreateOptions, MachineEvent, MachineEventValue, MachineGenerationPrecondition, MachineInspection, MachineLifecycleIntent, MachineLifetimePolicy, MachineObservation, MachineRevisionPrecondition, MachineState, ManagementObservation, ManagementReport, NativeMachineObservation, NetworkDestination, NetworkPolicy, NetworkRule, ObservationCause, ObservationReference, OperationDelivery, OperationInspection, OperationObservation, OutputChunk, OutputPage, OutputSegmentInspection, Qualification, ReleaseStatus, ResourceCapabilities, ResourceChangeAssessment, ResourceEnvelope, ResourceProvenance, ResourceUsage, RetainedQualification, RuntimeConfiguration, SecretRevocation, SecretVersion, SnapshotConsistency, SnapshotInspection, SnapshotKind, StorageInspection, StoragePayload, TreeChange, TreeEntry, TreeManifest } from "./contracts.js";
import { validateProtocol } from "./protocol-validation.js";
import { parseExecutionInspection, parseExecutionLineage } from "./execution.js";
import type { Machine } from "./machines.js";
import { integer, record, SandsurfHostError, text } from "./native-host.js";
import { createSandsurfGuestPath, sandsurfDigest, validateSandsurfOutputBoundary } from "./sandsurf-protocol.js";
import { digest, observed, protocol, validateIdentity } from "./sdk-internal.js";
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { isAbsolute, resolve } from "node:path";

export function parseOperationRecord(raw: unknown, expectedId: string, expectedMachine: string | undefined, owner: OperationInspection["owner"]): OperationInspection {
  if (!record(raw)) throw protocol("operation record");
  const kind = text(raw.kind);
  const value = owner === "host-authority" ? raw.value : raw;
  if (!record(value)) throw protocol("operation value");
  let operationId: string; let machineId: string | null; let requestDigest: string | null;
  let observation: OperationObservation;
  if (owner === "host-authority") {
    const identity = kind === "snapshot" ? value.request : value;
    if (!record(identity)) throw protocol("operation identity");
    operationId = validateIdentity(text(identity.operationId));
    machineId = ["image-import", "image-release", "secret-put"].includes(kind) ? null : validateIdentity(text(identity.machineId));
    requestDigest = digest(text(value.requestDigest));
    switch (kind) {
      case "lifecycle": observation = { kind, intent: parseLifecycleIntent(value, machineId!) }; break;
      case "configuration":
        if (!record(value.configuration) || integer(value.revision) < 1) throw protocol("configuration operation");
        observation = { kind, revision: integer(value.revision), configuration: parseRuntimeConfiguration(value.configuration) }; break;
      case "transfer": observation = { kind, applied: operationBoolean(value.applied) }; break;
      case "image-import": {
        const phase = text(value.phase);
        if (phase !== "admitted" && phase !== "published") throw protocol("image import phase");
        const image = value.image === null ? null : parseImage(value.image);
        if ((phase === "published") !== (image !== null)) throw protocol("image import completion");
        observation = { kind, phase, image }; break;
      }
      case "image-release": observation = { kind, imageDigest: digest(text(value.imageDigest)), cleanupPending: operationBoolean(value.cleanupPending) }; break;
      case "secret-delivery": {
        const disclosure = value.disclosure;
        if (!record(value.delivery) || !record(value.delivery.secret) || (disclosure !== "not-sent" && disclosure !== "possible" && disclosure !== "guest-reported-received")) throw protocol("secret delivery observation");
        observation = { kind, secret: parseSecret(value.delivery.secret), disclosure, revoked: operationBoolean(value.revoked),
          revocationOperation: value.revocationOperation === null ? null : validateIdentity(text(value.revocationOperation)) }; break;
      }
      case "secret-put":
        if (!record(value.secret)) throw protocol("secret put observation");
        observation = { kind, secret: parseSecret(value.secret), applied: operationBoolean(value.applied) }; break;
      case "secret-revocation": observation = { kind, revocation: parseSecretRevocation(value) }; break;
      case "snapshot": observation = { kind, snapshot: parseSnapshot(value) }; break;
      case "rollback": {
        const phase = text(value.phase); const evidenceDigest = operationEvidence(value.evidenceDigest);
        if ((phase !== "admitted" && phase !== "applied") || integer(value.expectedRevision) < 1 || (phase === "applied" && evidenceDigest === null)) throw protocol("rollback observation");
        observation = { kind, snapshotId: validateIdentity(text(value.snapshotId)), expectedRevision: integer(value.expectedRevision), phase, evidenceDigest }; break;
      }
      default: throw protocol("host operation kind");
    }
  } else {
    if (expectedMachine === undefined) throw protocol("guardian operation scope");
    machineId = expectedMachine;
    switch (kind) {
      case "guest": {
        const operation = value.operation;
        if (!record(operation) || !record(operation.admission) || !record(operation.admission.request) || !record(operation.admission.request.request)) throw protocol("guest operation admission");
        const command = operation.admission.request;
        if (!record(command.request)) throw protocol("guest operation request");
        operationId = validateIdentity(text(command.operationId)); machineId = validateIdentity(text(command.machineId)); requestDigest = digest(text(command.requestDigest));
        const generation = integer(command.generation); const requestKind = text(command.request.kind); const delivery = text(operation.delivery);
        if (generation < 1 || !["spawn", "close-input", "write-input", "acquire-terminal-input", "release-terminal-input", "resize-terminal", "signal", "terminate", "filesystem"].includes(requestKind) ||
            !["admitted", "dispatched", "applied", "not-applied", "unknown"].includes(delivery)) throw protocol("guest operation observation");
        const metadata = { request: command.request, binary: operation.admission.binary };
        if (requestDigest !== sandsurfDigest("operation", ["sandsurf-guest-command-v1", machineId, generation, operationId, metadata])) throw protocol("guest operation admission digest");
        observation = { kind, generation, requestKind: requestKind as Extract<OperationObservation, { kind: "guest" }>["requestKind"], delivery: delivery as OperationDelivery, evidenceDigest: operationEvidence(operation.evidenceDigest) }; break;
      }
      case "receipt-acknowledgement":
        operationId = validateIdentity(text(value.operationId)); requestDigest = null;
        observation = { kind, executionId: validateIdentity(text(value.executionId)), receiptDigest: digest(text(value.receiptDigest)) }; break;
      case "output-seal": {
        operationId = validateIdentity(text(value.operationId)); requestDigest = digest(text(value.requestDigest));
        const segment = parseOutputSegmentMetadata(value.segment);
        if (segment.machineId !== machineId) throw protocol("output operation machine identity");
        observation = { kind, segment }; break;
      }
      case "evidence-release": {
        if (!record(value.request) || !record(value.status)) throw protocol("release operation");
        operationId = validateIdentity(text(value.request.operationId));
        const status = parseReleaseStatus(value.status); requestDigest = status.requestDigest;
        observation = { kind, executionId: validateIdentity(text(value.executionId)), status }; break;
      }
      default: throw protocol("guardian operation kind");
    }
  }
  if (operationId !== expectedId || (expectedMachine !== undefined && machineId !== expectedMachine)) throw protocol("operation identity differs from requested scope");
  return { operationId, machineId, owner, requestDigest, observation };
}

function operationBoolean(value: unknown): boolean { if (typeof value !== "boolean") throw protocol("operation boolean"); return value; }

function operationEvidence(value: unknown): string | null { return value === null ? null : digest(text(value)); }

export function runtimeResponse(value: Record<string, unknown>): Record<string, unknown> {
  if (value.kind !== "runtime" || !record(value.response)) throw protocol("native runtime response");
  return value.response;
}

export function normalizeEventRead(options: { readonly after?: number; readonly maximum?: number }): { after: number; maximum: number } {
  const after = options.after ?? 0; const maximum = options.maximum ?? 256;
  if (!Number.isSafeInteger(after) || after < 0) throw new TypeError("event cursor must be a non-negative safe integer");
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 256) throw new TypeError("event page maximum must be 1 through 256");
  return { after, maximum };
}

const resourceFields = ["vcpus", "memoryMiB", "diskBytes", "outputBytes", "managedExecutions", "cpuQuotaMicros", "hostOverheadBytes", "physicalStorageBytes", "snapshotBytes", "channels", "inflightRequests", "networkConnections", "networkBytesPerSecond", "networkQueueBytes"] as const;

export function normalizeResources(value: ResourceEnvelope): Required<ResourceEnvelope> {
  if (Object.keys(value).some((key) => !(resourceFields as readonly string[]).includes(key))) throw new TypeError("unknown host resource field");
  const outputBytes = value.outputBytes ?? 1024 * 1024 * 1024; const managedExecutions = value.managedExecutions ?? 1024;
  const cpuQuotaMicros = value.cpuQuotaMicros ?? value.vcpus * 100_000;
  const hostOverheadBytes = value.hostOverheadBytes ?? value.vcpus * 512 * 1024 * 1024;
  const snapshotBytes = value.snapshotBytes ?? 2 * (value.diskBytes + value.memoryMiB * 1024 * 1024 + value.vcpus * 64 * 1024 * 1024);
  const physicalStorageBytes = value.physicalStorageBytes ?? 2 * value.diskBytes + outputBytes + snapshotBytes + value.vcpus * 64 * 1024 * 1024;
  const channels = value.channels ?? value.vcpus * 32; const inflightRequests = value.inflightRequests ?? value.vcpus * 16;
  const networkConnections = value.networkConnections ?? value.vcpus * 256;
  const networkBytesPerSecond = value.networkBytesPerSecond ?? value.vcpus * 64 * 1024 * 1024;
  const networkQueueBytes = value.networkQueueBytes ?? value.vcpus * 16 * 1024 * 1024;
  const result = { vcpus: value.vcpus, memoryMiB: value.memoryMiB, diskBytes: value.diskBytes, outputBytes, managedExecutions, cpuQuotaMicros, hostOverheadBytes, snapshotBytes, physicalStorageBytes, channels, inflightRequests, networkConnections, networkBytesPerSecond, networkQueueBytes };
  for (const item of Object.values(result)) if (!Number.isSafeInteger(item) || item <= 0) throw new TypeError("resource values must be positive safe integers");
  if (cpuQuotaMicros % 10 !== 0 || cpuQuotaMicros < 1000 || cpuQuotaMicros > value.vcpus * 100_000) throw new TypeError("CPU time quota requires 10µs granularity, at least 1000µs, within vCPU scheduling capacity");
  const storage = 2 * value.diskBytes + outputBytes + snapshotBytes;
  const memory = value.memoryMiB * 1024 * 1024 + hostOverheadBytes;
  if (!Number.isSafeInteger(storage) || physicalStorageBytes < storage || !Number.isSafeInteger(memory) || memory % 4096 !== 0) throw new TypeError("physical storage or total host memory envelope is invalid");
  return result;
}

function parseResources(value: Record<string, unknown>): Required<ResourceEnvelope> {
  // No legacy decoder: host responses must contain the complete envelope.
  if (Object.keys(value).some((key) => !(resourceFields as readonly string[]).includes(key))) throw protocol("unknown host resource field");
  for (const name of resourceFields) if (!(name in value)) throw protocol("complete host resource envelope");
  return normalizeResources(value as unknown as Required<ResourceEnvelope>);
}

export function normalizeExecutionDefaults(options: Pick<MachineCreateOptions, "environment" | "user" | "workingDirectory">): ImageDefaults {
  const environment = { ...(options.environment ?? {}) };
  const entries = Object.entries(environment);
  if (entries.length > 4096 || entries.some(([name, value]) => name.length < 1 || name.length > 512 || name.includes("\0") || name.includes("=") || typeof value !== "string" || value.length > 64 * 1024 || value.includes("\0"))) throw new TypeError("Machine environment is malformed");
  const user = options.user ?? null;
  if (user !== null && (typeof user !== "string" || user.length < 1 || user.length > 256 || user.includes("\0"))) throw new TypeError("Machine user is malformed");
  const workingDirectory = options.workingDirectory ?? null;
  if (workingDirectory !== null) createSandsurfGuestPath(workingDirectory);
  return { environment, user, workingDirectory };
}

export function normalizeLifetime(value: MachineLifetimePolicy | undefined): Readonly<{ expiresAtUnixMillis: number | null; expirationAction: "stop" | "destroy" }> {
  const expiresAtUnixMillis = value?.expiresAtUnixMs ?? null;
  const expirationAction = value?.expirationAction ?? "stop";
  if (expiresAtUnixMillis !== null && (!Number.isSafeInteger(expiresAtUnixMillis) || expiresAtUnixMillis <= 0)) throw new TypeError("absolute Machine expiration must be a positive Unix millisecond value");
  if (expirationAction !== "stop" && expirationAction !== "destroy") throw new TypeError("Machine expiration action is invalid");
  return { expiresAtUnixMillis, expirationAction };
}

export function machineViewFrom(response: Record<string, unknown>, expectedId?: string): MachineInspection {
  if (response.kind === "lifecycle") {
    if (!record(response.operation)) throw protocol("lifecycle operation");
    const delivery = parseOperationDelivery(response.operation.delivery);
    if (delivery !== "applied") throw new SandsurfHostError(delivery === "not-applied" ? "not-applied" : "ambiguous", `Lifecycle operation was ${delivery}`);
  }
  const value = response.kind === "machine" ? response.value : response.kind === "lifecycle" ? response.machine : undefined;
  const view = parseView(value);
  if (expectedId !== undefined && view.id !== expectedId) throw protocol("machine response identity");
  return view;
}

export function parseView(value: unknown): MachineInspection {
  try {
    if (!record(value) || !record(value.runtimeConfiguration) || !record(value.machine) || !record(value.executionDefaults) || !record(value.executionDefaults.environment) || !record(value.lifetime)) throw protocol("machine view");
    const id = validateIdentity(text(value.id)); const configurationRevision = integer(value.configurationRevision);
    const reservation = text(value.reservation); const expirationAction = text(value.lifetime.expirationAction);
    if (configurationRevision < 1 || (reservation !== "held" && reservation !== "released") || (expirationAction !== "stop" && expirationAction !== "destroy")) throw protocol("machine authority view");
    const environment: Record<string, string> = Object.fromEntries(Object.entries(value.executionDefaults.environment).map(([name, entry]) => [name, text(entry)]));
    const executionDefaults = normalizeExecutionDefaults({ environment,
      ...(value.executionDefaults.user === null ? {} : { user: text(value.executionDefaults.user) }),
      ...(value.executionDefaults.workingDirectory === null ? {} : { workingDirectory: text(value.executionDefaults.workingDirectory) }),
    });
    const lifecycleIntent = parseLifecycleIntent(value.lifecycleIntent, id);
    if (lifecycleIntent.revision > configurationRevision) throw protocol("lifecycle intent exceeds host revision");
    return {
      id, imageDigest: digest(text(value.imageDigest)), configurationRevision, reservation, knownSensitive: operationBoolean(value.knownSensitive),
      runtimeConfiguration: parseRuntimeConfiguration(value.runtimeConfiguration),
      lifecycleIntent, machine: parseMachineObservation(value.machine, id), management: parseManagementObservation(value.management), storage: parseStorageInspection(value.storage),
      executionDefaults, lifetime: { expiresAtUnixMillis: value.lifetime.expiresAtUnixMillis === null ? null : integer(value.lifetime.expiresAtUnixMillis), expirationAction },
      lastActivityUnixMillis: integer(value.lastActivityUnixMillis),
    };
  } catch (error) {
    if (error instanceof SandsurfHostError) throw error;
    throw protocol("machine view");
  }
}

function parseManagementObservation(raw: unknown): ManagementObservation {
  if (!record(raw)) throw protocol("management observation");
  const report = (value: unknown): ManagementReport => {
    if (!record(value) || !record(value.identity) || integer(value.generation) < 1) throw protocol("management report");
    return { generation: integer(value.generation), observedUnixMillis: integer(value.observedUnixMillis),
      identity: { bootId: validateIdentity(text(value.identity.bootId)), instanceId: validateIdentity(text(value.identity.instanceId)) } };
  };
  if (raw.kind === "current") return { kind: "current", value: report(raw.value) };
  if (raw.kind === "unavailable") return { kind: "unavailable", lastKnown: raw.lastKnown === null ? null : report(raw.lastKnown) };
  throw protocol("management availability");
}

function parseLifecycleIntent(value: unknown, machineId: string): MachineLifecycleIntent {
  if (!record(value) || text(value.machineId) !== machineId || !["running", "paused", "stopped", "suspended", "destroyed"].includes(text(value.desired)) || integer(value.revision) < 1) throw protocol("machine lifecycle intent");
  const completion = parseObservationReference(value.completion, machineId);
  return { machineId, operationId: validateIdentity(text(value.operationId)), desired: value.desired as DesiredMachineState, revision: integer(value.revision), requestDigest: digest(text(value.requestDigest)), completion };
}

function parseStorageInspection(value: unknown): StorageInspection {
  if (!record(value)) throw protocol("machine storage observation");
  if (value.kind === "unavailable" && ["ownership-missing", "ownership-invalid", "access-unavailable"].includes(text(value.reason)) && Object.keys(value).every((key) => ["kind", "reason"].includes(key))) return { kind: "unavailable", reason: value.reason as "ownership-missing" | "ownership-invalid" | "access-unavailable" };
  if (value.kind !== "current" || !["preparing", "published", "replacing", "retiring", "retired"].includes(text(value.phase)) || !record(value.payload)) throw protocol("machine storage observation");
  const capacityBytes = integer(value.capacityBytes);
  if (capacityBytes < 4096 || capacityBytes > 128 * 1024 ** 3 || capacityBytes % 4096 !== 0 || Object.keys(value).some((key) => !["kind", "phase", "capacityBytes", "operationId", "payload"].includes(key))) throw protocol("machine storage geometry");
  let payload: StoragePayload;
  if ((value.payload.kind === "present" || value.payload.kind === "capacity-mismatch") && Object.keys(value.payload).every((key) => ["kind", "fileBytes"].includes(key))) payload = { kind: value.payload.kind, fileBytes: integer(value.payload.fileBytes) };
  else if ((value.payload.kind === "missing" || value.payload.kind === "unavailable") && Object.keys(value.payload).length === 1) payload = { kind: value.payload.kind };
  else throw protocol("machine storage payload");
  return { kind: "current", phase: value.phase as Extract<StorageInspection, { kind: "current" }>["phase"], capacityBytes, operationId: value.operationId === null ? null : validateIdentity(text(value.operationId)), payload };
}

export function currentMachine(view: MachineInspection): { readonly generation: number } { if (view.machine.kind !== "current" || !record(view.machine.value)) throw new SandsurfHostError("unavailable", "Machine machine observation is unavailable"); return { generation: integer(view.machine.value.generation) }; }

export function nativeObservationOrder(observation: MachineObservation): readonly [number, number] {
  const value = observation.kind === "current" ? observation.value : observation.lastKnown;
  if (!record(value)) return [0, 0];
  return [integer(value.generation), integer(value.sequence)];
}

function parseReasons(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.some((reason) => typeof reason !== "string" || reason.length === 0)) throw protocol("capability reasons");
  return value as string[];
}

export function parseQualification(value: unknown): Qualification {
  if (!record(value)) throw protocol("qualification");
  if (value.kind === "qualified" && Object.keys(value).every((key) => key === "kind" || key === "evidence")) {
    if (typeof value.evidence !== "string" || !/^[a-f0-9]{64}$/u.test(value.evidence)) throw protocol("qualification evidence");
    return { kind: "qualified", evidence: value.evidence };
  }
  if (value.kind === "unqualified" && Object.keys(value).every((key) => key === "kind" || key === "reasons")) return { kind: "unqualified", reasons: parseReasons(value.reasons) };
  throw protocol("qualification");
}

export function parseCapability(value: unknown): Capability {
  if (!record(value)) throw protocol("capability support");
  if (value.kind === "supported" && Object.keys(value).every((key) => key === "kind" || key === "qualification")) return { kind: "supported", qualification: parseQualification(value.qualification) };
  if (value.kind === "unsupported" && Object.keys(value).every((key) => key === "kind" || key === "reasons")) return { kind: "unsupported", reasons: parseReasons(value.reasons) };
  throw protocol("capability support");
}

function parseMachineObservation(observation: Record<string, unknown>, machineId: string): MachineObservation {
  const parse = (value: unknown): NativeMachineObservation => {
    if (!record(value) || !record(value.cause) || value.machineId !== machineId) throw protocol("native machine observation identity");
    const state = text(value.state);
    if (!["creating", "starting", "running", "paused", "stopped", "suspended", "restoring", "destroying", "destroyed", "failed"].includes(state)) throw protocol("native machine observation state");
    const causeKind = value.cause.kind;
    const cause: ObservationCause | undefined = causeKind === "native" || causeKind === "guest-reset" ? { kind: causeKind }
      : causeKind === "lifecycle" || causeKind === "configuration"
        ? { kind: causeKind, operationId: validateIdentity(text(value.cause.operationId)) }
        : undefined;
    if (cause === undefined || Object.keys(value.cause).some((key) => key !== "kind" && ((cause.kind === "native" || cause.kind === "guest-reset") || key !== "operationId"))) throw protocol("native observation cause");
    const generation = integer(value.generation); const sequence = integer(value.sequence);
    if (generation < 1 || sequence < 1) throw protocol("native machine observation fence");
    return { machineId, generation, sequence, state: state as MachineState, appliedRevision: integer(value.appliedRevision), cause, evidenceDigest: digest(text(value.evidenceDigest)) };
  };
  if (observation.kind === "current") return { kind: "current", value: parse(observation.value) };
  if (observation.kind === "unavailable") return { kind: "unavailable", lastKnown: observation.lastKnown === null ? null : parse(observation.lastKnown) };
  throw protocol("native machine observation availability");
}

export function expectedCounter(value: number | undefined, name: string): number | undefined { if (value === undefined) return undefined; if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${name} must be a positive safe integer`); return value; }

export async function resolveRevisionPrecondition(machine: Machine, supplied: number | undefined): Promise<number> { const expected = expectedCounter(supplied, "expected revision"); return expected ?? machine[observed].configurationRevision; }

export function resolveGenerationPrecondition(machine: Machine, supplied: MachineGenerationPrecondition): { readonly expectedGeneration: number } {
  const generation = expectedCounter(supplied.expectedGeneration, "expected generation");
  return { expectedGeneration: generation ?? currentMachine(machine[observed]).generation };
}

export function resolveMachinePreconditions(machine: Machine, supplied: MachineGenerationPrecondition & MachineRevisionPrecondition): { readonly expectedRevision: number; readonly expectedGeneration: number } {
  return { ...resolveGenerationPrecondition(machine, supplied), expectedRevision: expectedCounter(supplied.expectedRevision, "expected revision") ?? machine[observed].configurationRevision };
}

function parseExecutionObservation(value: unknown): ExecutionObservation { if (!record(value) || (value.kind !== "current" && value.kind !== "unavailable")) throw protocol("process observation"); if (value.kind === "current") return { kind: "current", value: parseExecutionInspection(value.value) }; return { kind: "unavailable", lastKnown: value.lastKnown === null ? null : parseExecutionInspection(value.lastKnown) }; }

export function parseExecutionStatus(value: unknown, machineId: string): ExecutionStatus {
  if (!record(value)) throw protocol("execution status");
  const generation = integer(value.generation);
  if (generation < 1) throw protocol("execution status generation");
  const executionId = validateIdentity(text(value.executionId));
  const lineage = parseExecutionLineage(value.lineage, { machineId, generation, executionId });
  const report = parseExecutionObservation(value.report);
  let interruption: NativeMachineObservation | null = null;
  if (value.interruption !== null) {
    if (!record(value.interruption)) throw protocol("native execution interruption");
    const parsed = parseMachineObservation({ kind: "current", value: value.interruption }, machineId);
    if (parsed.kind !== "current" || !nativeBoundaryAffects(parsed.value, generation)) throw protocol("native execution interruption");
    interruption = parsed.value;
  }
  const reported = report.kind === "current" ? report.value : report.lastKnown;
  if (reported !== null && (reported.request.generation !== generation || reported.request.executionId !== executionId || reported.request.machineId !== machineId)) throw protocol("execution status identity");
  if (reported !== null && sandsurfDigest("snapshot", reported.lineage) !== sandsurfDigest("snapshot", lineage)) throw protocol("execution observation lineage differs from host admission");
  return { executionId, generation, lineage, report, interruption };
}

export function nativeBoundaryAffects(value: unknown, generation: number): boolean {
  return record(value) && (integer(value.generation) > generation ||
    (value.generation === generation && (value.state === "stopped" || value.state === "destroyed" || value.state === "failed")));
}

export function runtimeEventBelongsToProcess(event: MachineEvent, executionId: string): boolean {
  const value = event.value;
  if ((value.kind === "output" || value.kind === "receipt" || value.kind === "evidence-release") && value.executionId === executionId) return true;
  return value.kind === "machine" || (value.kind === "execution" && value.execution.request.executionId === executionId);
}

export function parseMachineEventValue(value: Record<string, unknown>, machineId: string): MachineEventValue {
  const fields: Record<string, readonly string[]> = {
    machine: ["observation"], "guest-operation": ["operation"], "lifecycle-operation": ["operation"], "configuration-operation": ["operation"],
    process: ["process"], output: ["executionId", "boundary"], receipt: ["executionId", "receiptDigest"],
    "evidence-release": ["executionId", "requestDigest", "cleanupPending"],
  };
  const required = fields[text(value.kind)];
  if (required === undefined || required.some((key) => !Object.hasOwn(value, key)) || Object.keys(value).some((key) => key !== "kind" && !required.includes(key))) throw protocol("runtime event fields");
  switch (value.kind) {
    case "machine": {
      const parsed = parseMachineObservation({ kind: "current", value: value.observation }, machineId);
      if (parsed.kind !== "current") throw protocol("native event observation");
      return { kind: "machine", observation: parsed.value };
    }
    case "guest-operation": {
      const operation = value.operation;
      if (!record(operation) || !record(operation.admission) || !record(operation.admission.request)) throw protocol("guest event admission");
      return { kind: "guest-operation", operation: parseOperationRecord({ kind: "guest", operation }, validateIdentity(text(operation.admission.request.operationId)), machineId, "guardian-journal") };
    }
    case "lifecycle-operation": case "configuration-operation": {
      const raw = value.operation;
      if (!record(raw) || !record(raw.command) || !record(raw.command.configuration) || raw.command.machineId !== machineId) throw protocol("configuration event identity");
      const revision = integer(raw.command.revision);
      if (revision < 1) throw protocol("configuration event revision");
      const operation: ConfigurationDeliveryObservation = {
        operationId: validateIdentity(text(raw.command.operationId)), revision, requestDigest: digest(text(raw.command.requestDigest)),
        configuration: parseRuntimeConfiguration(raw.command.configuration), delivery: parseOperationDelivery(raw.delivery),
        evidenceDigest: operationEvidence(raw.evidenceDigest), observation: parseObservationReference(raw.observation, machineId),
      };
      if (value.kind === "configuration-operation") return { kind: value.kind, operation };
      const desired = text(raw.command.desired);
      if (!["running", "paused", "stopped", "suspended", "destroyed"].includes(desired)) throw protocol("lifecycle event intent");
      return { kind: value.kind, operation: { ...operation, desired: desired as DesiredMachineState } };
    }
    case "process": {
      const execution = parseExecutionInspection(value.process);
      if (execution.request.machineId !== machineId) throw protocol("execution event identity");
      return { kind: "execution", execution };
    }
    case "output":
      validateSandsurfOutputBoundary(value.boundary);
      return { kind: "output", executionId: validateIdentity(text(value.executionId)), boundary: { ...value.boundary } };
    case "receipt": return { kind: "receipt", executionId: validateIdentity(text(value.executionId)), receiptDigest: digest(text(value.receiptDigest)) };
    case "evidence-release": return { kind: "evidence-release", executionId: validateIdentity(text(value.executionId)), requestDigest: digest(text(value.requestDigest)), cleanupPending: operationBoolean(value.cleanupPending) };
    default: throw protocol("runtime event kind");
  }
}

function parseOperationDelivery(value: unknown): OperationDelivery {
  const delivery = text(value);
  if (!["admitted", "dispatched", "applied", "not-applied", "unknown"].includes(delivery)) throw protocol("operation delivery");
  return delivery as OperationDelivery;
}

function parseObservationReference(value: unknown, machineId: string): ObservationReference | null {
  if (value === null) return null;
  if (!record(value) || value.machineId !== machineId || integer(value.generation) < 1 || integer(value.sequence) < 1) throw protocol("observation reference identity");
  return { machineId, generation: integer(value.generation), sequence: integer(value.sequence), digest: digest(text(value.digest)) };
}

export function parseOutputSegmentResponse(response: unknown): OutputSegmentInspection {
  if (!record(response) || response.kind !== "runtime" || !record(response.response) || response.response.kind !== "output-segment" || !record(response.response.segment)) throw protocol("output segment response");
  return parseOutputSegmentMetadata(response.response.segment);
}

function parseOutputSegmentMetadata(value: unknown): OutputSegmentInspection {
  if (!record(value) || integer(value.generation) < 1) throw protocol("output segment metadata");
  validateSandsurfOutputBoundary(value.output);
  return { id: validateIdentity(text(value.id)), machineId: validateIdentity(text(value.machineId)),
    executionId: validateIdentity(text(value.executionId)), generation: integer(value.generation), output: value.output };
}

export function parseEvidencePage(value: Record<string, unknown>): OutputPage {
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

export function normalizeOutputRead(options: { readonly after?: number; readonly maximum?: number }): { readonly after: number; readonly maximum: number } { const after = options.after ?? 0; const maximum = options.maximum ?? 64 * 1024; if (!Number.isSafeInteger(after) || after < 0) throw new TypeError("output cursor must be a nonnegative safe integer"); if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 256 * 1024) throw new TypeError("output page size must be 1 through 256 KiB"); return { after, maximum }; }

export function normalizeNetworkPolicy(value: NetworkPolicy): NetworkPolicy {
  if (!Array.isArray(value.rules) || value.rules.length > 4096) throw new TypeError("network policy exceeds its rule bound");
  const rules = value.rules.map((rule: NetworkRule) => {
    if (!(["tcp", "udp"] as const).includes(rule.plane) || !Array.isArray(rule.ports) || rule.ports.length === 0 || rule.ports.length > 4096) throw new TypeError("network rule is malformed");
    const ports = rule.ports.map((port: number | { readonly from: number; readonly to: number }) => { const range = typeof port === "number" ? { from: port, to: port } : port; if (!Number.isInteger(range.from) || !Number.isInteger(range.to) || range.from < 1 || range.from > range.to || range.to > 65535) throw new TypeError("network port range is malformed"); return range; });
    if (rule.destination.kind !== "ip") throw new TypeError("native network rules require a destination CIDR");
    if (rule.destination.allowPrivateAddresses !== undefined && typeof rule.destination.allowPrivateAddresses !== "boolean") throw new TypeError("private network authority must be a Boolean");
    const [address, prefixText, extra] = rule.destination.cidr.split("/");
    const family = address === undefined ? 0 : isIP(address); const prefix = Number(prefixText);
    if (extra !== undefined || family === 0 || prefixText === undefined || !/^\d+$/u.test(prefixText) || !Number.isInteger(prefix) || prefix < 0 || prefix > (family === 4 ? 32 : 128)) throw new TypeError("network CIDR is malformed");
    const destination: NetworkDestination = { kind: "ip", cidr: canonicalNetworkCidr(address!, prefix, family), allowPrivateAddresses: rule.destination.allowPrivateAddresses ?? false };
    return { plane: rule.plane, destination, ports };
  });
  if (rules.reduce((total, rule) => total + rule.ports.length, 0) > 16384) throw new TypeError("network policy exceeds its total port range bound");
  for (const rule of rules) {
    const ranges = [...rule.ports].sort((a, b) => a.from - b.from || a.to - b.to);
    const merged: { from: number; to: number }[] = [];
    for (const range of ranges) {
      const last = merged.at(-1);
      if (last !== undefined && range.from <= last.to + 1) last.to = Math.max(last.to, range.to);
      else merged.push({ from: range.from, to: range.to });
    }
    rule.ports = merged;
  }
  const unique = new Map(rules.map((rule) => [JSON.stringify(rule), rule]));
  return { rules: [...unique.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, rule]) => rule) };
}

function canonicalNetworkCidr(address: string, prefix: number, family: number): string {
  if (address.includes("%")) throw new TypeError("scoped network CIDR is unsupported");
  const width = family === 4 ? 32 : 128;
  let words: number[];
  if (family === 4) words = address.split(".").map(Number);
  else {
    let text = address.toLowerCase();
    if (text.includes(".")) {
      const last = text.lastIndexOf(":");
      const octets = text.slice(last + 1).split(".").map(Number);
      text = text.slice(0, last + 1) + ((octets[0]! << 8) | octets[1]!).toString(16) + ":" + ((octets[2]! << 8) | octets[3]!).toString(16);
    }
    const halves = text.split("::");
    const left = halves[0] === "" ? [] : halves[0]!.split(":").map((part) => Number.parseInt(part, 16));
    const right = halves.length === 1 || halves[1] === "" ? [] : halves[1]!.split(":").map((part) => Number.parseInt(part, 16));
    words = halves.length === 1 ? left : [...left, ...Array<number>(8 - left.length - right.length).fill(0), ...right];
  }
  const wordBits = family === 4 ? 8 : 16;
  let bits = words.reduce((value, word) => (value << BigInt(wordBits)) | BigInt(word), 0n);
  bits = prefix === 0 ? 0n : (bits >> BigInt(width - prefix)) << BigInt(width - prefix);
  const mask = (1n << BigInt(wordBits)) - 1n;
  const out = Array.from({ length: width / wordBits }, (_, i) => Number((bits >> BigInt(width - wordBits * (i + 1))) & mask));
  if (family === 4) return out.join(".") + "/" + prefix;
  if (out.slice(0, 5).every((v) => v === 0) && out[5] === 0xffff) {
    return `::ffff:${out[6]! >> 8}.${out[6]! & 255}.${out[7]! >> 8}.${out[7]! & 255}/${prefix}`;
  }
  let bestStart = -1; let bestLength = 1;
  for (let i = 0; i < out.length;) {
    if (out[i] !== 0) { i++; continue; }
    let end = i; while (end < out.length && out[end] === 0) end++;
    if (end - i > bestLength) { bestStart = i; bestLength = end - i; }
    i = end;
  }
  const formatted = bestStart < 0 ? out.map((v) => v.toString(16)).join(":")
    : out.slice(0, bestStart).map((v) => v.toString(16)).join(":") + "::" + out.slice(bestStart + bestLength).map((v) => v.toString(16)).join(":");
  return formatted + "/" + prefix;
}

export function normalizeExposure(value: ExposureSpec): Exposure["spec"] { const guestAddress = value.guestAddress ?? "100.64.0.2"; const hostAddress = value.hostAddress ?? "127.0.0.1"; const guestPort = value.guestPort; const hostPort = value.hostPort ?? 0; const publicValue = value.public ?? false; if (!["100.64.0.2", "fd00::2"].includes(guestAddress) || isIP(hostAddress) === 0 || (!publicValue && !["127.0.0.1", "::1"].includes(hostAddress)) || !Number.isInteger(guestPort) || guestPort < 1 || guestPort > 65535 || !Number.isInteger(hostPort) || hostPort < 0 || hostPort > 65535) throw new TypeError("port exposure is malformed"); return { guestAddress, guestPort, hostAddress, hostPort, public: publicValue }; }

function parseRuntimeConfiguration(value: Record<string, unknown>): RuntimeConfiguration { if (!record(value.network) || !Array.isArray(value.network.rules) || !Array.isArray(value.exposures) || !record(value.resources)) throw protocol("runtime configuration"); return { network: normalizeNetworkPolicy(value.network as unknown as NetworkPolicy), exposures: value.exposures.map(parseExposure), resources: parseResources(value.resources) }; }

export function parseExposure(value: unknown): Exposure { if (!record(value) || !record(value.spec)) throw protocol("exposure"); return { id: validateIdentity(text(value.id)), machineId: validateIdentity(text(value.machineId)), revision: integer(value.revision), spec: normalizeExposure({ guestAddress: text(value.spec.guestAddress), guestPort: integer(value.spec.guestPort), hostAddress: text(value.spec.hostAddress), hostPort: integer(value.spec.hostPort), public: value.spec.public === true }), active: value.active === true, boundPort: value.boundPort === null ? null : integer(value.boundPort) }; }

export function parseSecret(value: Record<string, unknown>): SecretVersion { return { id: validateIdentity(text(value.id)), version: validateIdentity(text(value.version)), bytes: integer(value.bytes) }; }

export function parseSecretRevocation(value: Record<string, unknown>): SecretRevocation {
  const evidence = value.guestCleanupReport;
  if (!record(value.secret) || (evidence !== null && !record(evidence))) throw protocol("secret revocation evidence");
  const parsedEvidence = evidence === null ? null : {
    filesRemoved: integer(evidence.filesRemoved),
    environmentBindingsRemoved: integer(evidence.environmentBindingsRemoved),
    recipientsTerminated: identityList(evidence.recipientsTerminated),
    recipientsAlreadyStopped: identityList(evidence.recipientsAlreadyStopped),
    residualCopiesPossible: operationBoolean(evidence.residualCopiesPossible),
    actionsReportedComplete: operationBoolean(evidence.actionsReportedComplete),
  };
  return { operationId: validateIdentity(text(value.operationId)), machineId: validateIdentity(text(value.machineId)), secret: parseSecret(value.secret), terminateRecipients: operationBoolean(value.terminateRecipients), futureDeliveryRevoked: true, guestCleanupReport: parsedEvidence };
}

function identityList(value: unknown): readonly string[] { if (!Array.isArray(value) || value.length > 1024) throw protocol("identity list"); return value.map((item) => validateIdentity(text(item))); }

function parseCpuLedgers(value: unknown): CpuLedgers | null {
  if (value === null) return null;
  validateProtocol("CpuLedgers", value);
  return value;
}

export function parseUsage(value: Record<string, unknown>): ResourceUsage { if (!record(value.provenance)) throw protocol("resource measurement provenance"); const nullable = (item: unknown): number | null => item === null ? null : integer(item); return { provenance: parseResourceProvenance(value.provenance), hostCounterEpoch: value.hostCounterEpoch === null ? null : digest(text(value.hostCounterEpoch)), channelsCurrent: nullable(value.channelsCurrent), inflightRequestsCurrent: nullable(value.inflightRequestsCurrent), cpuMicros: value.cpuMicros === null ? null : integer(value.cpuMicros), cpuLedgers: parseCpuLedgers(value.cpuLedgers), memoryCurrent: value.memoryCurrent === null ? null : integer(value.memoryCurrent), memoryPeak: value.memoryPeak === null ? null : integer(value.memoryPeak), diskLogicalBytes: integer(value.diskLogicalBytes), diskAllocatedBytes: integer(value.diskAllocatedBytes), ioReadBytes: value.ioReadBytes === null ? null : integer(value.ioReadBytes), ioWriteBytes: value.ioWriteBytes === null ? null : integer(value.ioWriteBytes), outputRetainedBytes: integer(value.outputRetainedBytes), networkRxBytes: integer(value.networkRxBytes), networkTxBytes: integer(value.networkTxBytes), networkConnections: integer(value.networkConnections), executionsCurrent: integer(value.executionsCurrent), complete: value.complete === true, source: text(value.source), observedUnixMillis: integer(value.observedUnixMillis) }; }

export function parseResourceCapabilities(value: Record<string, unknown>): ResourceCapabilities {
  return { nativeTopology: parseCapability(value.nativeTopology), cpuTime: parseCapability(value.cpuTime), aggregateHostMemory: parseCapability(value.aggregateHostMemory), managedAdmission: parseCapability(value.managedAdmission), outputRetention: parseCapability(value.outputRetention), storageReservations: parseCapability(value.storageReservations), networkEnvelope: parseCapability(value.networkEnvelope), aggregatePhysicalStorage: parseCapability(value.aggregatePhysicalStorage), sharedHostWorkers: parseCapability(value.sharedHostWorkers), completeEnforcement: parseCapability(value.completeEnforcement) };
}

export function parseResourceAssessment(value: Record<string, unknown>): ResourceChangeAssessment {
  const mode = text(value.mode);
  if (mode !== "live" && mode !== "requires-reboot" && mode !== "unsupported") throw protocol("resource change mode");
  if (!Array.isArray(value.reasons) || value.reasons.length > 64) throw protocol("resource change reasons");
  return { mode, reasons: value.reasons.map(text) };
}

function parseResourceProvenance(value: Record<string, unknown>): ResourceProvenance {
  validateProtocol("ResourceProvenance", value);
  return value;
}

export function parseRetainedQualification(value: unknown): RetainedQualification {
  if (!record(value) || !record(value.run) || !record(value.run.configuration) || !record(value.run.configuration.resources)) throw protocol("retained native qualification");
  const run = value.run; const config = value.run.configuration;
  const scope = text(run.scope); const engine = text(config.engine);
  if (scope !== "lifecycle" && scope !== "resources" && scope !== "cpu-time" && scope !== "host-memory" && scope !== "storage-budgets" && scope !== "managed-channels" && scope !== "native-network" && scope !== "disk-snapshots" && scope !== "full-state" && scope !== "images" && scope !== "distribution") throw protocol("qualification scope");
  if (engine !== "firecracker" && engine !== "qemu-hvf" && engine !== "qemu-whpx") throw protocol("qualification engine");
  if (!Array.isArray(run.passedChecks) || run.passedChecks.length > 64) throw protocol("hardware checks");
  return { run: { configuration: { buildDigest: digest(text(config.buildDigest)), platform: text(config.platform), architecture: text(config.architecture), hardwareDigest: digest(text(config.hardwareDigest)), engine, engineDigest: digest(text(config.engineDigest)), imageDigest: digest(text(config.imageDigest)), kernelDigest: digest(text(config.kernelDigest)), initramfsDigest: config.initramfsDigest === null ? null : digest(text(config.initramfsDigest)), nicConfigurationDigest: digest(text(config.nicConfigurationDigest)), storageConfigurationDigest: digest(text(config.storageConfigurationDigest)), resources: parseResources(value.run.configuration.resources) }, scope, observedUnixMillis: integer(run.observedUnixMillis), passedChecks: run.passedChecks.map(text), evidenceDigest: digest(text(run.evidenceDigest)) }, acceptedBy: text(value.acceptedBy), acceptedUnixMillis: integer(value.acceptedUnixMillis), recordDigest: digest(text(value.recordDigest)) };
}

export function normalizeOciSource(options: ImageImportOptions): Readonly<Record<string, unknown>> {
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

export function parseImage(value: unknown): ImageInspection {
  if (!record(value)) throw protocol("image record");
  return { digest: digest(text(value.digest)), sourceDigest: digest(text(value.sourceDigest)), platform: text(value.platform), architecture: text(value.architecture), logicalBytes: integer(value.logicalBytes), storageBytes: integer(value.storageBytes), provenanceDigest: digest(text(value.provenanceDigest)), sensitive: operationBoolean(value.sensitive) };
}

export function parseSnapshot(value: unknown): SnapshotInspection {
  if (!record(value) || !record(value.request) || !record(value.resources)) throw protocol("snapshot record");
  const consistency = value.consistency === null ? null : text(value.consistency) as SnapshotConsistency;
  if (consistency !== null && !["crash", "machine"].includes(consistency)) throw protocol("snapshot consistency");
  const kind = text(value.request.kind) as SnapshotKind; if (kind !== "disk" && kind !== "full") throw protocol("snapshot kind");
  const phase = text(value.phase) as SnapshotInspection["phase"]; if (!["admitted", "capturing", "ready"].includes(phase)) throw protocol("snapshot phase");
  return { id: validateIdentity(text(value.request.id)), operationId: validateIdentity(text(value.request.operationId)), machineId: validateIdentity(text(value.request.machineId)), expectedGeneration: integer(value.request.expectedGeneration), expectedRevision: integer(value.request.expectedRevision), kind, parent: value.request.parent === null ? null : validateIdentity(text(value.request.parent)), requestDigest: digest(text(value.requestDigest)), phase, imageDigest: digest(text(value.imageDigest)), resources: parseResources(value.resources), consistency, systemDiskDigest: value.systemDiskDigest === null ? null : digest(text(value.systemDiskDigest)), systemDiskBytes: integer(value.systemDiskBytes), manifestDigest: value.manifestDigest === null ? null : digest(text(value.manifestDigest)), sensitive: operationBoolean(value.sensitive) };
}

export function parseReleaseStatus(value: Record<string, unknown>): ReleaseStatus { return { requestDigest: digest(text(value.requestDigest)), cleanupPending: operationBoolean(value.cleanupPending) }; }

export function normalizeExclusions(values: readonly string[]): ReadonlySet<string> {
  const result = new Set<string>();
  for (const value of values) {
    validatePortableTreePath(value);
    result.add(value);
  }
  return result;
}

export function treeManifest(entries: readonly TreeEntry[], captureOperationId?: string): TreeManifest {
  const ordered = [...entries].sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  const paths = new Set<string>(); for (const entry of ordered) { validateTreeEntry(entry); if (paths.has(entry.path)) throw new TypeError("artifact manifest paths must be unique"); paths.add(entry.path); }
  const hash = createHash("sha256").update("SANDSURF-TREE-MANIFEST-V1\0");
  for (const entry of ordered) hash.update(Buffer.from(treeEntryDigest(entry), "hex"));
  return { digest: hash.digest("hex"), entries: ordered, ...(captureOperationId === undefined ? {} : { captureOperationId: validateIdentity(captureOperationId) }) };
}

export function treeEntryDigest(entry: TreeEntry): string { return sandsurfDigest("transfer", ["sandsurf-tree-entry-v1", entry]); }

export function treeChangeSet(base: TreeManifest, changes: readonly TreeChange[], captureOperationId: string): ChangeSet {
  const hash = createHash("sha256").update("SANDSURF-TREE-CHANGES-V1\0");
  const paths = new Set<string>();
  for (const change of changes) { const path = change.kind === "upsert" ? change.entry.path : change.path; validatePortableTreePath(path); if (change.kind === "upsert") validateTreeEntry(change.entry); if (paths.has(path)) throw new TypeError("artifact change paths must be unique"); paths.add(path); hash.update(Buffer.from(sandsurfDigest("transfer", ["sandsurf-tree-change-v1", change]), "hex")); }
  const changesDigest = hash.digest("hex"); return { baseManifestDigest: base.digest, base: base.entries, changes: [...changes], digest: sandsurfDigest("transfer", ["sandsurf-tree-change-set-v1", base.digest, changesDigest]), captureOperationId: validateIdentity(captureOperationId) };
}

export function validateTreeManifest(value: TreeManifest): void { const rebuilt = treeManifest(value.entries); if (rebuilt.digest !== digest(value.digest)) throw new TypeError("artifact manifest digest mismatch"); }


function validateTreeEntry(entry: TreeEntry): void {
  validatePortableTreePath(entry.path); if (!Number.isSafeInteger(entry.mode) || entry.mode < 0 || entry.mode > 0o7777 || !Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > 128 * 1024 ** 3) throw new TypeError("artifact entry metadata is invalid");
  if (entry.kind === "directory") { if (entry.size !== 0 || entry.digest !== null || entry.target !== null) throw new TypeError("artifact directory entry is malformed"); return; }
  if (entry.kind === "file") { if (entry.digest === null || entry.target !== null) throw new TypeError("artifact file entry is malformed"); digest(entry.digest); return; }
  if (entry.kind !== "symlink" || entry.digest === null || entry.target === null || entry.target.length === 0 || entry.target.length > 4096 || entry.target.length !== entry.size || entry.target.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255) || createHash("sha256").update(Uint8Array.from(entry.target)).digest("hex") !== entry.digest) throw new TypeError("artifact symlink entry is malformed");
}

export function validatePortableTreePath(value: string): void {
  if (value.length === 0 || value.startsWith("/") || value.endsWith("/") || value.includes("\\") || value.includes("\0") || value.normalize("NFC") !== value || value.split("/").some((part) => part.length === 0 || part === "." || part === ".." || windowsReserved(part))) throw new TypeError("artifact paths must be normalized portable relative paths");
}

function windowsReserved(value: string): boolean { const stem = (value.split(".")[0] ?? value).toUpperCase(); return value.endsWith(" ") || value.endsWith(".") || value.includes(":") || ["CON", "PRN", "AUX", "NUL"].includes(stem) || /^(?:COM|LPT)[1-9]$/u.test(stem); }

export function pathDepth(path: string): number { return path.split("/").length; }

export function parseTreeEntry(value: unknown): TreeEntry {
  if (!record(value) || typeof value.path !== "string" || !["directory", "file", "symlink"].includes(String(value.kind))) throw protocol("host tree entry");
  const target = value.target === null ? null : Array.isArray(value.target) && value.target.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255) ? value.target as number[] : (() => { throw protocol("host tree link target"); })();
  return { path: value.path, kind: value.kind as TreeEntry["kind"], mode: integer(value.mode), size: integer(value.size), digest: value.digest === null ? null : digest(text(value.digest)), target };
}

export function parseHostCapture(value: Record<string, unknown>): ArtifactInspection {
  return { id: validateIdentity(text(value.operationId)), machineId: validateIdentity(text(value.machineId)), requestDigest: digest(text(value.requestDigest)), manifestDigest: digest(text(value.manifestDigest)), entries: integer(value.entries), bytes: integer(value.bytes), consistency: "live" };
}
