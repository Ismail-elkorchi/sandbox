import type { FileExpectation, FileOperationOptions, MachineGenerationPrecondition } from "./contracts.js";
import { parseDirectoryPage, parseFileMetadata, parseFileRange, parseFileRevision, parseFilesystemBytes, parseFilesystemWatchPage } from "./filesystem.js";
import type { DirectoryPage, FileMetadata, FileRange, FileRevision, FilesystemWatcherIdentity, FilesystemWatchEvent, FilesystemWatchPage } from "./filesystem.js";
import type { Machine } from "./machines.js";
import { integer, record, SandsurfHostError, text } from "./native-host.js";
import { resolveGenerationPrecondition } from "./observations.js";
import { createSandsurfGuestPath } from "./sandsurf-protocol.js";
import type { FilesystemRequest, FileTransfer } from "./protocol-generated.js";
import { childIdentity, digest, dispatchGuest, identity, protocol, queryGuest, validateIdentity } from "./sdk-internal.js";
import { createHash } from "node:crypto";

export class MachineFilesystem {
  readonly #machine: Machine;
  readonly #directory: Uint8Array | undefined;
  constructor(machine: Machine, directory?: Uint8Array) { this.#machine = machine; this.#directory = directory?.slice(); }
  /** A path convenience only; it neither limits filesystem authority nor normalizes Linux symlinks. */
  at(directory: string | Uint8Array): MachineFilesystem { return new MachineFilesystem(this.#machine, Uint8Array.from(this.#path(directory))); }
  #path(path: string | Uint8Array): readonly number[] {
    const bytes = typeof path === "string" ? new TextEncoder().encode(path) : path;
    if (bytes[0] === 0x2f || this.#directory === undefined) return createSandsurfGuestPath(bytes);
    const joined = new Uint8Array(this.#directory.byteLength + 1 + bytes.byteLength);
    joined.set(this.#directory); joined[this.#directory.byteLength] = 0x2f; joined.set(bytes, this.#directory.byteLength + 1);
    return createSandsurfGuestPath(joined);
  }
  async stat(path: string | Uint8Array, follow = true): Promise<FileMetadata> {
    const response = await this.#operation({ kind: "stat", path: [...this.#path(path)], follow });
    if (response.kind !== "stat") throw protocol("file metadata response");
    return parseFileMetadata(response.value);
  }
  lstat(path: string | Uint8Array): Promise<FileMetadata> { return this.stat(path, false); }
  async list(path: string | Uint8Array, options: { readonly after?: Uint8Array; readonly maximum?: number } = {}): Promise<DirectoryPage> {
    const maximum = options.maximum ?? 256;
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 4096) throw new TypeError("directory page bound must be 1..4096");
    const response = await this.#operation({ kind: "list", path: [...this.#path(path)], after: options.after === undefined ? null : [...options.after], maximum });
    if (response.kind !== "list") throw protocol("directory page response");
    return parseDirectoryPage(response.page, maximum, options.after);
  }
  async read(path: string | Uint8Array, options: MachineGenerationPrecondition & { readonly offset?: number; readonly maximum?: number } = {}): Promise<FileRange> {
    const offset = options.offset ?? 0; const maximum = options.maximum ?? 64 * 1024;
    if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 64 * 1024) throw new TypeError("file range bounds are invalid");
    const response = await this.#operation({ kind: "read", path: [...this.#path(path)], offset, maximum }, undefined, options);
    if (response.kind !== "read") throw protocol("file range response");
    return parseFileRange(response.range, offset, maximum);
  }
  async *readStream(path: string | Uint8Array, options: MachineGenerationPrecondition & { readonly maximumBytes?: number; readonly chunkBytes?: number; readonly expectedDigest?: string } = {}): AsyncGenerator<Uint8Array> {
    const guestPath = this.#path(path);
    const authority = resolveGenerationPrecondition(this.#machine, options);
    const maximumBytes = options.maximumBytes ?? 128 * 1024 ** 3;
    const maximum = options.chunkBytes ?? 64 * 1024;
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0 || maximumBytes > 128 * 1024 ** 3
      || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 64 * 1024) throw new TypeError("file stream bounds are invalid");
    const expectedDigest = options.expectedDigest === undefined ? undefined : digest(options.expectedDigest);
    let offset = 0; let observation: { readonly size: number; readonly token: string } | undefined;
    const hash = createHash("sha256");
    for (;;) {
      const range = await this.read(Uint8Array.from(guestPath), { ...authority, offset, maximum });
      const observed = range.observation;
      if (observed.size > maximumBytes) throw new SandsurfHostError("capacity", "file exceeds the requested stream bound");
      if (observation !== undefined && (observed.size !== observation.size || observed.token !== observation.token)) throw new SandsurfHostError("conflict", "file changed during streamed read");
      observation = observed;
      const bytes = range.bytes;
      if (bytes.byteLength > maximum || offset + bytes.byteLength > maximumBytes) throw protocol("file range exceeds its credit");
      hash.update(bytes); offset += bytes.byteLength;
      if (bytes.byteLength !== 0) yield bytes;
      if (range.eof) break;
      if (bytes.byteLength === 0) throw protocol("empty non-terminal file range");
    }
    const actualDigest = hash.digest("hex");
    if (observation === undefined || observation.size !== offset) throw protocol("file stream did not capture its reported size");
    if (expectedDigest !== undefined && actualDigest !== expectedDigest) throw new SandsurfHostError("integrity", "captured file bytes do not match the caller's expected digest");
  }
  async readFile(path: string | Uint8Array, options: MachineGenerationPrecondition & { readonly maximumBytes?: number; readonly expectedDigest?: string } = {}): Promise<Uint8Array> {
    const chunks: Uint8Array[] = []; let length = 0;
    for await (const chunk of this.readStream(path, { ...options, maximumBytes: options.maximumBytes ?? 64 * 1024 ** 2 })) { chunks.push(chunk); length += chunk.byteLength; }
    const result = new Uint8Array(length); let cursor = 0;
    for (const chunk of chunks) { result.set(chunk, cursor); cursor += chunk.byteLength; }
    return result;
  }
  async writeFile(path: string | Uint8Array, bytes: string | Uint8Array, options: FileOperationOptions & { readonly mode?: number; readonly expected?: FileExpectation; readonly transferId?: string } = {}): Promise<FileRevision> {
    const value = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
    return this.writeStream(path, [value], { length: value.byteLength, digest: createHash("sha256").update(value).digest("hex"), ...options });
  }
  async writeStream(path: string | Uint8Array, chunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>, options: FileOperationOptions & { readonly length: number; readonly digest: string; readonly mode?: number; readonly expected?: FileExpectation; readonly transferId?: string }): Promise<FileRevision> {
    if (!Number.isSafeInteger(options.length) || options.length < 0 || options.length > 128 * 1024 ** 3) throw new TypeError("stream length is invalid");
    const operationId = validateIdentity(options.operationId ?? identity("write-file"));
    const transfer: FileTransfer = { id: validateIdentity(options.transferId ?? childIdentity(operationId, "transfer")), path: [...this.#path(path)], length: options.length, digest: digest(options.digest), mode: options.mode ?? 0o644, expected: options.expected ?? { kind: "any" } };
    let remoteOperationStarted = false;
    const perform = async (request: FilesystemRequest, child: string): Promise<Record<string, unknown>> => {
      remoteOperationStarted = true;
      return this.#operation(request, childIdentity(operationId, child), options);
    };
    await perform({ kind: "begin-write", transfer }, "begin");
    remoteOperationStarted = false;
    try {
      let offset = 0; let buffered = new Uint8Array(64 * 1024); let bufferedBytes = 0;
      const flush = async (): Promise<void> => {
        if (bufferedBytes === 0) return;
        const bytes = buffered.slice(0, bufferedBytes);
        await perform({ kind: "write-chunk", transfer, offset, bytes: [...bytes] }, `chunk-${offset}`);
        remoteOperationStarted = false; offset += bytes.byteLength; buffered = new Uint8Array(64 * 1024); bufferedBytes = 0;
      };
      for await (const supplied of chunks) {
        if (!(supplied instanceof Uint8Array)) throw new TypeError("stream chunks must be Uint8Array values");
        let cursor = 0;
        while (cursor < supplied.byteLength) { const take = Math.min(buffered.byteLength - bufferedBytes, supplied.byteLength - cursor); buffered.set(supplied.subarray(cursor, cursor + take), bufferedBytes); bufferedBytes += take; cursor += take; if (bufferedBytes === buffered.byteLength) await flush(); }
      }
      await flush();
      if (offset !== options.length) throw new SandsurfHostError("transfer", "stream byte count does not match its declaration");
      const response = await perform({ kind: "commit-write", transfer }, "commit");
      if (response.kind !== "written") throw protocol("committed file revision");
      const revision = parseFileRevision(response.revision);
      if (revision.size !== transfer.length || revision.digest !== transfer.digest) throw protocol("committed file revision identity");
      return revision;
    } catch (error) {
      // Once a remote operation has begun, delivery may be ambiguous. Keep the
      // staged transfer so the caller can reconcile/retry the stable child IDs.
      if (!remoteOperationStarted) { try { await this.#operation({ kind: "abort-write", transfer }, childIdentity(operationId, "abort"), options); } catch { /* Preserve the original failure. */ } }
      throw error;
    }
  }
  async mkdir(path: string | Uint8Array, options: FileOperationOptions & { readonly recursive?: boolean } = {}): Promise<void> { await this.#complete({ kind: "mkdir", path: [...this.#path(path)], recursive: options.recursive ?? false }, validateIdentity(options.operationId ?? identity("mkdir")), options); }
  async rename(from: string | Uint8Array, to: string | Uint8Array, options: FileOperationOptions = {}): Promise<void> { await this.#complete({ kind: "rename", from: [...this.#path(from)], to: [...this.#path(to)] }, validateIdentity(options.operationId ?? identity("rename")), options); }
  async remove(path: string | Uint8Array, options: FileOperationOptions & { readonly recursive?: boolean } = {}): Promise<void> { await this.#complete({ kind: "remove", path: [...this.#path(path)], recursive: options.recursive ?? false }, validateIdentity(options.operationId ?? identity("remove")), options); }
  async chmod(path: string | Uint8Array, mode: number, options: FileOperationOptions = {}): Promise<void> { await this.#complete({ kind: "chmod", path: [...this.#path(path)], mode }, validateIdentity(options.operationId ?? identity("chmod")), options); }
  async readlink(path: string | Uint8Array): Promise<Uint8Array> {
    const response = await this.#operation({ kind: "readlink", path: [...this.#path(path)] });
    if (response.kind !== "link") throw protocol("readlink response");
    const target = parseFilesystemBytes(response.target, 4096);
    if (target.byteLength === 0 || target.includes(0)) throw protocol("readlink target");
    return target;
  }
  async symlink(path: string | Uint8Array, target: Uint8Array, options: FileOperationOptions = {}): Promise<void> {
    if (!(target instanceof Uint8Array) || target.byteLength === 0 || target.byteLength > 4096 || target.includes(0)) throw new TypeError("symlink target must be 1..4096 bytes without NUL");
    await this.#complete({ kind: "symlink", path: [...this.#path(path)], target: [...target] }, validateIdentity(options.operationId ?? identity("symlink")), options);
  }
  async watch(path: string | Uint8Array, options: FileOperationOptions & { readonly recursive?: boolean; readonly watcherId?: string } = {}): Promise<FilesystemWatcher> {
    const authority = resolveGenerationPrecondition(this.#machine, options); const watcherId = validateIdentity(options.watcherId ?? identity("watcher"));
    await this.#complete({ kind: "watch", watcherId, generation: authority.expectedGeneration, path: [...this.#path(path)], recursive: options.recursive ?? false }, validateIdentity(options.operationId ?? identity("watch")), authority);
    return new FilesystemWatcher(this, watcherId, authority.expectedGeneration);
  }
  attachWatcher(value: FilesystemWatcherIdentity): FilesystemWatcher {
    const id = validateIdentity(value.id);
    const generation = integer(value.generation);
    if (generation === 0) throw new TypeError("watcher generation must be positive");
    return new FilesystemWatcher(this, id, generation, integer(value.cursor));
  }
  async pollWatcher(watcherId: string, generation: number, after: number, maximum = 256): Promise<FilesystemWatchPage> {
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 4096) throw new TypeError("watch event bound must be 1..4096");
    const response = await this.#operation({ kind: "poll-watch", watcherId, generation, after: integer(after), maximum }, undefined, { expectedGeneration: generation });
    if (response.kind !== "watch") throw protocol("watch response");
    return parseFilesystemWatchPage(response.page, watcherId, generation, maximum, after);
  }
  async closeWatcher(watcherId: string, generation: number, options: FileOperationOptions = {}): Promise<void> {
    if (options.expectedGeneration !== undefined && options.expectedGeneration !== generation) throw new SandsurfHostError("stale-generation", "Watcher generation cannot be rebound");
    await this.#complete({ kind: "unwatch", watcherId, generation }, validateIdentity(options.operationId ?? identity("unwatch")), { expectedGeneration: generation });
  }
  async #complete(request: FilesystemRequest, operationId: string, precondition: MachineGenerationPrecondition): Promise<void> {
    const response = await this.#operation(request, operationId, precondition);
    if (response.kind !== "complete" || Object.keys(response).length !== 1) throw protocol("filesystem command acknowledgement");
  }
  async #operation(request: FilesystemRequest, operationId = identity("file"), precondition: MachineGenerationPrecondition = {}): Promise<Record<string, unknown>> {
    if (typeof request.kind === "string" && ["stat", "list", "read", "readlink", "poll-watch"].includes(request.kind)) {
      const response = await this.#machine[queryGuest]({ kind: "filesystem-query", request }, precondition);
      if (response.kind !== "file" || !record(response.response)) throw protocol("filesystem response"); return response.response;
    }
    const operation = await this.#machine[dispatchGuest]({ kind: "filesystem", request }, operationId, precondition); const admission = operation.admission;
    const command = record(admission) ? admission.request : undefined;
    if (!record(command)) throw protocol("filesystem operation receipt");
    const response = await this.#machine[queryGuest]({ kind: "operation", operationId, requestDigest: text(command.requestDigest) });
    if (response.kind !== "file" || !record(response.response)) throw protocol("filesystem response"); return response.response;
  }
}

export class FilesystemWatcher {
  readonly id: string; readonly generation: number; readonly #filesystem: MachineFilesystem; #closed = false; #cursor: number; #polling = false;
  constructor(filesystem: MachineFilesystem, id: string, generation: number, cursor = 0) { this.#filesystem = filesystem; this.id = id; this.generation = generation; this.#cursor = cursor; }
  get identity(): FilesystemWatcherIdentity { return { id: this.id, generation: this.generation, cursor: this.#cursor }; }
  async poll(maximum = 256): Promise<readonly FilesystemWatchEvent[]> {
    if (this.#closed || this.#polling) throw new SandsurfHostError("client", "Filesystem watcher is closed or already polling");
    this.#polling = true;
    try {
      const page = await this.#filesystem.pollWatcher(this.id, this.generation, this.#cursor, maximum);
      this.#cursor = page.cursor;
      return page.events;
    } finally { this.#polling = false; }
  }
  async close(options: FileOperationOptions = {}): Promise<void> { if (!this.#closed) { await this.#filesystem.closeWatcher(this.id, this.generation, options); this.#closed = true; } }
}
