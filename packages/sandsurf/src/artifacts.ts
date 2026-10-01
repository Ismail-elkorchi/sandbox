import type { ArtifactApplyOptions, ArtifactCaptureOptions, ArtifactImportOptions, ArtifactInspection, ChangeSet, ExecutionOperationOptions, HostApplyReport, TreeChange, TreeEntry, TreeManifest } from "./contracts.js";
import type { Machine } from "./machines.js";
import { integer, record, SandsurfHostError, text } from "./native-host.js";
import { currentMachine, expectedCounter, normalizeExclusions, parseHostCapture, parseTreeEntry, pathDepth, resolveGenerationPrecondition, resolveMachinePreconditions, treeChangeSet, treeEntryDigest, treeManifest, validatePortableTreePath, validateTreeManifest } from "./observations.js";
import { createSandsurfGuestPath } from "./sandsurf-protocol.js";
import type { Sandsurf } from "./sandsurf.js";
import { authorize, childIdentity, digest, identity, protocol, transport, validateIdentity } from "./sdk-internal.js";
import { createHash } from "node:crypto";
import { isAbsolute, resolve } from "node:path";

export class ArtifactCollection {
  readonly #host: Sandsurf;
  constructor(host: Sandsurf) { this.#host = host; }
  async get(machineId: string, id: string): Promise<Artifact> {
    validateIdentity(machineId); validateIdentity(id);
    const entries: TreeEntry[] = [];
    let inspection: ArtifactInspection | undefined; let after = 0;
    for (;;) {
      const page = await this.#host[transport]({ kind: "list-host-tree", machineId, operationId: id, after, maximum: 128 });
      if (page.kind !== "host-tree-entries" || !record(page.capture) || !Array.isArray(page.entries)) throw protocol("artifact entries");
      const observed = parseHostCapture(page.capture);
      if (observed.id !== id || observed.machineId !== machineId
        || (inspection !== undefined && (observed.manifestDigest !== inspection.manifestDigest || observed.requestDigest !== inspection.requestDigest))) throw protocol("artifact identity");
      inspection = observed;
      for (const entry of page.entries) entries.push(parseTreeEntry(entry));
      if (page.next === null) break;
      const next = integer(page.next);
      if (next <= after || page.entries.length === 0) throw protocol("artifact pagination");
      after = next;
    }
    const manifest = treeManifest(entries, id);
    if (inspection === undefined || entries.length !== inspection.entries || manifest.digest !== inspection.manifestDigest) throw protocol("artifact manifest coverage");
    return new Artifact(this.#host, inspection, manifest);
  }
}

export class MachineArtifacts {
  readonly #machine: Machine; readonly #host: Sandsurf;
  constructor(machine: Machine, host: Sandsurf) { this.#machine = machine; this.#host = host; }
  async capture(source: string | Uint8Array, options: ArtifactCaptureOptions = {}): Promise<Artifact> {
    const path = [...createSandsurfGuestPath(source)];
    const operationId = validateIdentity(options.operationId ?? identity("artifact"));
    const view = await this.#machine.inspect();
    const expectedRevision = expectedCounter(options.expectedRevision, "expected revision") ?? view.configurationRevision;
    const expectedGeneration = expectedCounter(options.expectedGeneration, "expected generation") ?? currentMachine(view).generation;
    const maximumBytes = options.maximumBytes ?? Math.min(view.runtimeConfiguration.resources.diskBytes, 128 * 1024 ** 3);
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0 || maximumBytes > 128 * 1024 ** 3) throw new TypeError("artifact capture bound is invalid");
    const response = await this.#machine[transport]({ kind: "capture-guest-tree", machineId: this.#machine.id, source: path, operationId, expectedRevision, expectedGeneration, maximumBytes });
    if (response.kind !== "host-tree-capture" || !record(response.capture)) throw protocol("artifact capture");
    const capture = parseHostCapture(response.capture);
    if (capture.id !== operationId || capture.machineId !== this.#machine.id) throw protocol("artifact capture identity");
    return this.#host.artifacts.get(this.#machine.id, operationId);
  }
  async importFromHost(options: ArtifactImportOptions): Promise<Artifact> {
    if (!isAbsolute(options.source)) throw new TypeError("host import source must be absolute");
    const source = resolve(options.source);
    const operationId = validateIdentity(options.operationId ?? identity("import"));
    const exclusions = [...normalizeExclusions(options.exclusions ?? [])].sort();
    const maximumBytes = options.maximumBytes ?? 8 * 1024 ** 3;
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0 || maximumBytes > 128 * 1024 ** 3) throw new TypeError("host import bound is invalid");
    const authority = await resolveMachinePreconditions(this.#machine, options);
    const approvalId = await this.#machine[authorize]({ kind: "host-import", machineId: this.#machine.id, operationId, request: { source, exclusions, maximumBytes, expectedRevision: authority.expectedRevision } });
    const response = await this.#machine[transport]({ kind: "capture-host-tree", machineId: this.#machine.id, operationId, expectedRevision: authority.expectedRevision, source, exclusions, maximumBytes, approvalId });
    if (response.kind !== "host-tree-capture" || !record(response.capture)) throw protocol("host artifact capture");
    const artifact = await this.#host.artifacts.get(this.#machine.id, operationId);
    await artifact.writeTo(this.#machine, options.destination, { operationId, expectedGeneration: authority.expectedGeneration });
    return artifact;
  }
}

export class Artifact {
  readonly id: string; readonly inspection: ArtifactInspection; readonly manifest: TreeManifest;
  readonly #host: Sandsurf;
  constructor(host: Sandsurf, inspection: ArtifactInspection, manifest: TreeManifest) {
    validateTreeManifest(manifest);
    this.#host = host; this.id = inspection.id; this.inspection = Object.freeze({ ...inspection });
    this.manifest = Object.freeze({ ...manifest, entries: Object.freeze(manifest.entries.map((entry) => Object.freeze({ ...entry, target: entry.target === null ? null : Object.freeze([...entry.target]) }))) });
  }
  compare(base?: Artifact): ChangeSet {
    const previous = base?.manifest ?? treeManifest([]);
    const old = new Map(previous.entries.map((entry) => [entry.path, entry]));
    const next = new Map(this.manifest.entries.map((entry) => [entry.path, entry]));
    const changes: TreeChange[] = [...old.keys()].filter((path) => !next.has(path))
      .sort((left, right) => pathDepth(right) - pathDepth(left) || Buffer.from(left).compare(Buffer.from(right)))
      .map((path) => ({ kind: "delete", path }));
    const upserts = this.manifest.entries.filter((entry) => { const prior = old.get(entry.path); return prior === undefined || treeEntryDigest(prior) !== treeEntryDigest(entry); });
    upserts.sort((left, right) => (left.kind === "directory" ? 0 : 1) - (right.kind === "directory" ? 0 : 1) || pathDepth(left.path) - pathDepth(right.path) || Buffer.from(left.path).compare(Buffer.from(right.path)));
    for (const entry of upserts) changes.push({ kind: "upsert", entry });
    return treeChangeSet(previous, changes, this.id);
  }
  async writeTo(machine: Machine, destination: string | Uint8Array, options: ExecutionOperationOptions = {}): Promise<void> {
    const filesystem = machine.fs.at(destination);
    const authority = resolveGenerationPrecondition(machine, options);
    const operationId = validateIdentity(options.operationId ?? identity("materialize-artifact"));
    await machine.fs.mkdir(destination, { recursive: true, operationId: childIdentity(operationId, "root"), ...authority });
    for (const entry of this.manifest.entries) if (entry.kind === "directory") await filesystem.mkdir(entry.path, { recursive: true, operationId: childIdentity(operationId, `mkdir-${entry.path}`), ...authority });
    for (const entry of this.manifest.entries) {
      if (entry.kind === "directory") continue;
      if (entry.kind === "symlink") {
        if (entry.target === null) throw protocol("artifact link target");
        await filesystem.symlink(entry.path, Uint8Array.from(entry.target), { operationId: childIdentity(operationId, `symlink-${entry.path}`), ...authority });
      } else {
        if (entry.digest === null) throw protocol("artifact file digest");
        await filesystem.writeStream(entry.path, this.#blob(entry.digest, entry.size), { length: entry.size, digest: entry.digest, mode: entry.mode, expected: { kind: "absent" }, operationId: childIdentity(operationId, `write-${entry.path}`), ...authority });
      }
    }
    for (const entry of [...this.manifest.entries].reverse()) if (entry.kind === "directory") await filesystem.chmod(entry.path, entry.mode, { operationId: childIdentity(operationId, `chmod-${entry.path}`), ...authority });
  }
  async applyToHost(options: ArtifactApplyOptions): Promise<HostApplyReport> {
    if (!isAbsolute(options.destination)) throw new TypeError("host apply destination must be absolute");
    const destination = resolve(options.destination); const operationId = validateIdentity(options.operationId ?? identity("apply"));
    const changeSet = this.compare(options.base);
    const machineId = this.inspection.machineId;
    const approvalId = await this.#host[authorize]({
      kind: "host-apply", machineId, operationId,
      request: { artifactId: this.id, manifestDigest: this.manifest.digest, destination, changeSetDigest: changeSet.digest },
    });
    const { captureOperationId: _captureOperationId, ...supplied } = changeSet;
    const response = await this.#host[transport]({ kind: "apply-artifact-to-host", machineId, artifactId: this.id, operationId, destination, changeSet: supplied, approvalId });
    if (response.kind !== "host-apply" || !record(response.report)) throw protocol("artifact host application");
    return { operationId: text(response.report.operationId), changeSetDigest: digest(text(response.report.changeSetDigest)), applied: integer(response.report.applied), recovered: response.report.recovered === true };
  }
  async *readStream(path: string): AsyncGenerator<Uint8Array> {
    validatePortableTreePath(path);
    const entry = this.manifest.entries.find((value) => value.path === path);
    if (entry?.kind !== "file" || entry.digest === null) throw new SandsurfHostError("missing", "artifact has no regular file at that path");
    yield* this.#blob(entry.digest, entry.size);
  }
  async readFile(path: string, options: { readonly maximumBytes?: number } = {}): Promise<Uint8Array> {
    const maximum = options.maximumBytes ?? 64 * 1024 ** 2;
    if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > 64 * 1024 ** 2) throw new TypeError("artifact in-memory read bound is invalid");
    const entry = this.manifest.entries.find((value) => value.path === path);
    if (entry === undefined || entry.size > maximum) throw new SandsurfHostError("capacity", "artifact file exceeds the read bound");
    const chunks: Uint8Array[] = []; let length = 0;
    for await (const chunk of this.readStream(path)) { chunks.push(chunk); length += chunk.byteLength; if (length > maximum) throw protocol("artifact read credit"); }
    return Buffer.concat(chunks, length);
  }
  async *#blob(expectedDigest: string, expectedLength: number): AsyncGenerator<Uint8Array> {
    let offset = 0; const hash = createHash("sha256");
    for (;;) {
      const response = await this.#host[transport]({ kind: "read-host-tree-blob", machineId: this.inspection.machineId, operationId: this.id, digest: expectedDigest, offset, maximum: 64 * 1024 });
      if (response.kind !== "host-blob" || response.digest !== expectedDigest || integer(response.offset) !== offset || (!Array.isArray(response.bytes) && !(response.bytes instanceof Uint8Array)) || typeof response.eof !== "boolean") throw protocol("artifact blob");
      const bytes = response.bytes instanceof Uint8Array ? response.bytes : Uint8Array.from(response.bytes as number[]);
      if (bytes.byteLength > 64 * 1024 || offset + bytes.byteLength > expectedLength || (bytes.byteLength === 0 && !response.eof)) throw protocol("artifact blob credit");
      hash.update(bytes); offset += bytes.byteLength;
      if (bytes.byteLength !== 0) yield bytes;
      if (response.eof) break;
    }
    if (offset !== expectedLength || hash.digest("hex") !== expectedDigest) throw new SandsurfHostError("integrity", "artifact bytes do not match their immutable digest");
  }
}
