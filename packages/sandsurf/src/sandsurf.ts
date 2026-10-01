import { ArtifactCollection } from "./artifacts.js";
import type { AuthorityChange, HostInspection, SandsurfAuthorizer, SandsurfOpenOptions } from "./contracts.js";
import { ImageCollection } from "./images.js";
import { MachineCollection, SnapshotCollection } from "./machines.js";
import { NativeHostClient, record, SandsurfHostError, text } from "./native-host.js";
import { parseCapability, parseQualification, parseResourceCapabilities, parseRetainedQualification } from "./observations.js";
import { SandsurfOperations } from "./operations.js";
import { authorize, childIdentity, digest, protocol, subscribe, transport, validateIdentity } from "./sdk-internal.js";
import { SecretCollection } from "./secrets.js";
import { resolve } from "node:path";

export class Sandsurf {
  readonly machines: MachineCollection;
  readonly images: ImageCollection;
  readonly snapshots: SnapshotCollection;
  readonly secrets: SecretCollection;
  readonly operations: SandsurfOperations;
  readonly artifacts: ArtifactCollection;
  readonly #client: NativeHostClient;
  readonly #authorizer: SandsurfAuthorizer | undefined;
  #closed = false;
  private constructor(client: NativeHostClient, authorizer: SandsurfAuthorizer | undefined) { this.#client = client; this.#authorizer = authorizer; this.machines = new MachineCollection(this); this.images = new ImageCollection(this); this.snapshots = new SnapshotCollection(this); this.secrets = new SecretCollection(this); this.operations = new SandsurfOperations(this); this.artifacts = new ArtifactCollection(this); }
  static async open(options: SandsurfOpenOptions): Promise<Sandsurf> { return new Sandsurf(await NativeHostClient.open(resolve(options.directory), options.service ?? "auto"), options.authorizer); }
  async inspect(): Promise<HostInspection> {
    this.#open(); const response = await this.#client.request({ kind: "inspect" });
    if (response.kind !== "inspection" || !record(response.value)) throw protocol("host inspection response");
    const value = response.value;
    const engine = text(value.engine);
    if (engine !== "firecracker" && engine !== "apple-virtualization" && engine !== "hyper-v") throw protocol("native engine");
    if (!record(value.guestPower)) throw protocol("guest power capabilities");
    if (!record(value.resources)) throw protocol("host resource capabilities");
    if (!Array.isArray(value.qualificationRecords) || value.qualificationRecords.length > 16 || !Array.isArray(value.qualificationIssues)) throw protocol("retained native qualifications");
    return {
      hostId: validateIdentity(text(value.hostId)), platform: text(value.platform), architecture: text(value.architecture),
      guestArchitecture: text(value.guestArchitecture), guestPlatform: text(value.guestPlatform), engine,
      lifecycle: parseQualification(value.lifecycle), fullState: parseQualification(value.fullState), images: parseQualification(value.images),
      imageWorkers: parseCapability(value.imageWorkers),
      qualificationRecords: value.qualificationRecords.map(parseRetainedQualification), qualificationIssues: value.qualificationIssues.map(text),
      resources: parseResourceCapabilities(value.resources),
      guestPower: { shutdown: parseCapability(value.guestPower.shutdown), reboot: parseCapability(value.guestPower.reboot) },
      console: parseCapability(value.console),
      defaultImageDigest: value.defaultImageDigest === null ? null : digest(text(value.defaultImageDigest)),
    };
  }
  async close(): Promise<void> { this.#closed = true; await this.#client.close(); }
  async [transport](request: Readonly<Record<string, unknown>>): Promise<Record<string, unknown>> { this.#open(); return this.#client.request(request); }
  [subscribe](machineId: string, after: number, maximum: number, signal?: AbortSignal): AsyncGenerator<Record<string, unknown>, void> { this.#open(); return this.#client.eventPages(machineId, after, maximum, signal); }
  async [authorize](change: AuthorityChange): Promise<string> {
    if (this.#authorizer === undefined) throw new SandsurfHostError("authorization", `No authorizer is installed for ${change.kind}`);
    const decision = await this.#authorizer(change);
    if (decision === false) throw new SandsurfHostError("authorization", `${change.kind} was denied`);
    if (decision === true) return childIdentity(change.operationId, `approval-${change.kind}`);
    if (!record(decision) || typeof decision.approvalId !== "string") throw new TypeError("authorizer returned an invalid decision");
    return validateIdentity(decision.approvalId);
  }
  #open(): void { if (this.#closed) throw new SandsurfHostError("client", "Sandsurf client is closed"); }
}
