import type { Exposure, ExposureSpec, MachineRevisionPrecondition, NetworkPolicy, RuntimeConfiguration } from "./contracts.js";
import type { Machine } from "./machines.js";
import { record, SandsurfHostError } from "./native-host.js";
import { expectedCounter, normalizeExposure, normalizeNetworkPolicy, parseExposure, parseView, resolveRevisionPrecondition } from "./observations.js";
import { authorize, identity, observe, protocol, transport, validateIdentity } from "./sdk-internal.js";

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
