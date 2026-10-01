import type { MachineRevisionPrecondition, ResourceChangeAssessment, ResourceEnvelope, ResourceUpdateResult, ResourceUsage } from "./contracts.js";
import type { Machine } from "./machines.js";
import { record } from "./native-host.js";
import { normalizeResources, parseResourceAssessment, parseUsage, parseView, resolveRevisionPrecondition } from "./observations.js";
import { authorize, identity, observe, protocol, transport, validateIdentity } from "./sdk-internal.js";

export class MachineResources {
  readonly #machine: Machine;
  constructor(machine: Machine) { this.#machine = machine; }
  async assess(resources: ResourceEnvelope): Promise<ResourceChangeAssessment> {
    const response = await this.#machine[transport]({ kind: "assess-resources", machineId: this.#machine.id, resources: normalizeResources(resources) });
    if (response.kind !== "resource-assessment" || !record(response.assessment)) throw protocol("resource change assessment");
    return parseResourceAssessment(response.assessment);
  }
  async usage(): Promise<ResourceUsage> {
    const response = await this.#machine[transport]({ kind: "get-usage", machineId: this.#machine.id });
    if (response.kind !== "usage" || !record(response.usage)) throw protocol("resource usage response");
    return parseUsage(response.usage);
  }
  async update(resources: ResourceEnvelope, options: MachineRevisionPrecondition & { readonly operationId?: string } = {}): Promise<ResourceUpdateResult> {
    const operationId = validateIdentity(options.operationId ?? identity("resources")); const expectedRevision = await resolveRevisionPrecondition(this.#machine, options.expectedRevision); const normalized = normalizeResources(resources);
    const approvalId = await this.#machine[authorize]({ kind: "resource-increase", machineId: this.#machine.id, operationId, request: { expectedRevision, resources: normalized } });
    const response = await this.#machine[transport]({ kind: "update-resources", machineId: this.#machine.id, operationId, expectedRevision, resources: normalized, approvalId });
    if (response.kind !== "resource-update" || !record(response.machine) || !record(response.assessment)) throw protocol("resource update response");
    return { machine: this.#machine[observe](parseView(response.machine)), assessment: parseResourceAssessment(response.assessment) };
  }
}
