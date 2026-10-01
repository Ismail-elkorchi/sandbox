import type { OperationInspection } from "./contracts.js";
import { record, SandsurfHostError } from "./native-host.js";
import { parseOperationRecord } from "./observations.js";
import type { Sandsurf } from "./sandsurf.js";
import { protocol, transport, validateIdentity } from "./sdk-internal.js";

export class SandsurfOperations {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async get(operationId: string, options: { readonly machineId?: string } = {}): Promise<Operation | undefined> {
    const id = validateIdentity(operationId);
    const machineId = options.machineId === undefined ? undefined : validateIdentity(options.machineId);
    const observation = await inspectOperation(this.#host, id, machineId);
    return observation === undefined ? undefined : new Operation(this.#host, observation, machineId);
  }
}

export class Operation {
  readonly id: string;
  readonly #host: Sandsurf;
  readonly #machineId: string | undefined;
  #observation: OperationInspection;
  constructor(host: Sandsurf, observation: OperationInspection, machineId?: string) {
    this.id = observation.operationId; this.#host = host; this.#machineId = machineId; this.#observation = observation;
  }
  get observation(): OperationInspection { return this.#observation; }
  async inspect(): Promise<OperationInspection> {
    const observation = await inspectOperation(this.#host, this.id, this.#machineId);
    if (observation === undefined) throw new SandsurfHostError("missing", `Operation ${this.id} is no longer observable`);
    this.#observation = observation;
    return observation;
  }
}

async function inspectOperation(host: Sandsurf, operationId: string, machineId?: string): Promise<OperationInspection | undefined> {
  const response = await host[transport](machineId === undefined ? { kind: "get-host-operation", operationId }
    : { kind: "get-operation", operationId, machineId });
  try {
    if (response.kind === "host-operation") {
      if (response.value === null) return undefined;
      return parseOperationRecord(response.value, operationId, machineId, "host-authority");
    }
    if (machineId === undefined || response.kind !== "runtime" || !record(response.response) || response.response.kind !== "operation") throw protocol("operation response");
    if (response.response.operation === null) return undefined;
    return parseOperationRecord(response.response.operation, operationId, machineId, "guardian-journal");
  } catch (error) {
    if (error instanceof SandsurfHostError) throw error;
    throw protocol("operation observation");
  }
}
