import { SandsurfHostError, integer, record, text } from "./native-host.js";
import { createSandsurfGuestPath } from "./sandsurf-protocol.js";

/** Metadata reported by the administrator-controlled guest, not host attestation. */
export interface FileMetadata {
  readonly kind: "regular" | "directory" | "symlink" | "other";
  readonly size: number;
  readonly readonly: boolean;
  readonly modifiedMillis: number | null;
  readonly mode: number;
  readonly device: number;
  readonly inode: number;
}
export interface DirectoryPage {
  readonly entries: readonly { readonly name: Uint8Array; readonly stat: FileMetadata }[];
  readonly next: Uint8Array | null;
}
export interface FileReadObservation { readonly size: number; readonly token: string; }
export interface FileRange {
  readonly offset: number;
  readonly bytes: Uint8Array;
  readonly eof: boolean;
  readonly observation: FileReadObservation;
}
export interface FileRevision { readonly size: number; readonly digest: string; }
export type FilesystemWatchEvent = {
  readonly watcherId: string;
  readonly generation: number;
  readonly sequence: number;
} & ({ readonly kind: "created" | "modified" | "removed"; readonly path: Uint8Array }
  | { readonly kind: "overflow"; readonly path: null });
export interface FilesystemWatchPage { readonly events: readonly FilesystemWatchEvent[]; readonly cursor: number; }
export interface FilesystemWatcherIdentity { readonly id: string; readonly generation: number; readonly cursor: number; }

function invalid(): never { throw new SandsurfHostError("protocol", "Invalid guest filesystem observation"); }
function object(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!record(value) || keys.some((key) => !(key in value)) || Object.keys(value).some((key) => !keys.includes(key))) invalid();
  return value;
}
function hash(value: unknown): string {
  const result = text(value); if (!/^[a-f0-9]{64}$/u.test(result)) invalid(); return result;
}
function identity(value: unknown): string {
  const result = text(value); if (!/^[A-Za-z0-9_-]{1,128}$/u.test(result)) invalid(); return result;
}
export function parseFilesystemBytes(value: unknown, maximum: number): Uint8Array {
  if (!(value instanceof Uint8Array) && !Array.isArray(value)) invalid();
  if (value.length > maximum || (Array.isArray(value) && value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255))) invalid();
  return Uint8Array.from(value as Uint8Array);
}
function name(value: unknown): Uint8Array {
  const bytes = parseFilesystemBytes(value, 255);
  if (bytes.length === 0 || bytes.includes(0) || bytes.includes(47) ||
      (bytes.length === 1 && bytes[0] === 46) || (bytes.length === 2 && bytes[0] === 46 && bytes[1] === 46)) invalid();
  return bytes;
}
export function parseFileMetadata(value: unknown): FileMetadata {
  const result = object(value, ["kind", "size", "readonly", "modifiedMillis", "mode", "device", "inode"]);
  if (!["regular", "directory", "symlink", "other"].includes(text(result.kind)) || typeof result.readonly !== "boolean") invalid();
  const mode = integer(result.mode); if (mode > 0xffffffff) invalid();
  return { kind: result.kind as FileMetadata["kind"], size: integer(result.size), readonly: result.readonly,
    modifiedMillis: result.modifiedMillis === null ? null : integer(result.modifiedMillis),
    mode, device: integer(result.device), inode: integer(result.inode) };
}
export function parseDirectoryPage(value: unknown, maximum: number, after?: Uint8Array): DirectoryPage {
  const result = object(value, ["entries", "next"]);
  if (!Array.isArray(result.entries) || result.entries.length > maximum) invalid();
  const entries = result.entries.map((value) => {
    const entry = object(value, ["name", "stat"]);
    return { name: name(entry.name), stat: parseFileMetadata(entry.stat) };
  });
  const next = result.next === null ? null : name(result.next);
  let previous = after;
  for (const entry of entries) {
    if (previous !== undefined && Buffer.compare(previous, entry.name) >= 0) invalid();
    previous = entry.name;
  }
  if (next !== null && (entries.length === 0 || Buffer.compare(next, entries.at(-1)!.name) !== 0)) invalid();
  return { entries, next };
}
export function parseFileRange(value: unknown, offset: number, maximum: number): FileRange {
  const result = object(value, ["offset", "bytes", "eof", "observation"]);
  const observation = object(result.observation, ["size", "token"]);
  const bytes = parseFilesystemBytes(result.bytes, maximum);
  const size = integer(observation.size);
  if (integer(result.offset) !== offset || typeof result.eof !== "boolean" ||
      offset + bytes.byteLength > size || result.eof !== (offset + bytes.byteLength === size) ||
      (!result.eof && bytes.byteLength === 0)) invalid();
  return { offset, bytes, eof: result.eof, observation: { size, token: hash(observation.token) } };
}
export function parseFileRevision(value: unknown): FileRevision {
  const result = object(value, ["size", "digest"]);
  return { size: integer(result.size), digest: hash(result.digest) };
}
export function parseFilesystemWatchEvents(value: unknown, watcherId: string, generation: number, maximum: number, after = 0): readonly FilesystemWatchEvent[] {
  if (!Array.isArray(value) || value.length > maximum) invalid();
  let previous = after;
  return value.map((value) => {
    const event = object(value, ["watcherId", "generation", "sequence", "kind", "path"]);
    const sequence = integer(event.sequence);
    if (identity(event.watcherId) !== watcherId || integer(event.generation) !== generation || sequence <= previous || (event.kind !== "overflow" && sequence !== previous + 1)) invalid();
    previous = sequence;
    const common = { watcherId, generation, sequence };
    if (event.kind === "overflow" && event.path === null) return { ...common, kind: "overflow", path: null };
    if (event.kind !== "created" && event.kind !== "modified" && event.kind !== "removed") invalid();
    const path = parseFilesystemBytes(event.path, 4096);
    try { createSandsurfGuestPath(path); } catch { invalid(); }
    return { ...common, kind: event.kind, path };
  });
}
export function parseFilesystemWatchPage(value: unknown, watcherId: string, generation: number, maximum: number, after: number): FilesystemWatchPage {
  const result = object(value, ["events", "cursor"]);
  const events = parseFilesystemWatchEvents(result.events, watcherId, generation, maximum, after);
  const cursor = integer(result.cursor);
  if (cursor !== (events.at(-1)?.sequence ?? after)) invalid();
  return { events, cursor };
}
