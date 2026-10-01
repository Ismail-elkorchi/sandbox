import type { MachineRevisionPrecondition, SecretDeliveryResult, SecretRevocation, SecretVersion } from "./contracts.js";
import type { Machine } from "./machines.js";
import { record, text } from "./native-host.js";
import { parseSecret, parseSecretRevocation, resolveRevisionPrecondition } from "./observations.js";
import { createSandsurfGuestPath, sandsurfDigest } from "./sandsurf-protocol.js";
import type { Sandsurf } from "./sandsurf.js";
import { authorize, identity, protocol, transport, validateIdentity } from "./sdk-internal.js";

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
