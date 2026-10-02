import { lstat, open } from "node:fs/promises";

type Section = { readonly address: number; readonly span: number; readonly offset: number; readonly bytes: number };
const MAX_FILE = 512 * 1024 ** 2;
const MAX_IMPORTS = 128;
const invalid = (): Error => new Error("invalid or unbounded native x64 PE import table");

/** Read only loader dependency descriptors and names. Debug/exception/export
 * tables can be enormous and are neither dependency names nor captured text.
 * Contract: native Windows x64 PE32+, including RVA-based delay imports.
 * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
 */
export async function peImports(path: string): Promise<readonly string[]> {
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.size < 64 || before.size > MAX_FILE) throw invalid();
  const file = await open(path, "r");
  try {
    const identity = await file.stat();
    if (identity.dev !== before.dev || identity.ino !== before.ino || identity.size !== before.size) throw invalid();
    const read = async (offset: number, bytes: number): Promise<Buffer> => {
      if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(bytes) || offset < 0 || bytes < 1 ||
          bytes > 65536 || offset + bytes > identity.size) throw invalid();
      const buffer = Buffer.allocUnsafe(bytes);
      let copied = 0;
      while (copied < bytes) {
        const result = await file.read(buffer, copied, bytes - copied, offset + copied);
        if (result.bytesRead === 0) throw invalid();
        copied += result.bytesRead;
      }
      return buffer;
    };
    const dos = await read(0, 64);
    if (dos.readUInt16LE(0) !== 0x5a4d) throw invalid();
    const pe = dos.readUInt32LE(60);
    if (pe < 64 || pe > 65536) throw invalid();
    const header = await read(pe, 24);
    if (header.readUInt32LE(0) !== 0x4550 || header.readUInt16LE(4) !== 0x8664) throw invalid();
    const count = header.readUInt16LE(6), optionalBytes = header.readUInt16LE(20);
    if (count < 1 || count > 96 || optionalBytes < 128 || optionalBytes > 4096) throw invalid();
    const optional = await read(pe + 24, optionalBytes);
    if (optional.readUInt16LE(0) !== 0x20b) throw invalid();
    const directories = optional.readUInt32LE(108), headers = optional.readUInt32LE(60);
    const table = pe + 24 + optionalBytes;
    if (directories < 2 || directories > 16 || 112 + directories * 8 > optionalBytes ||
        headers < table + count * 40 || headers > identity.size) throw invalid();
    const rawSections = await read(table, count * 40);
    const sections: Section[] = [];
    for (let index = 0; index < count; index++) {
      const entry = rawSections.subarray(index * 40, (index + 1) * 40);
      const section = { address: entry.readUInt32LE(12), span: Math.max(entry.readUInt32LE(8), entry.readUInt32LE(16)),
        offset: entry.readUInt32LE(20), bytes: entry.readUInt32LE(16) };
      if (section.span === 0) continue;
      if (section.address < headers || section.address + section.span > 0x1_0000_0000 ||
          section.bytes !== 0 && (section.offset < headers || section.offset + section.bytes > identity.size) ||
          sections.some((previous) => overlap(section.address, section.span, previous.address, previous.span) ||
            section.bytes !== 0 && previous.bytes !== 0 && overlap(section.offset, section.bytes, previous.offset, previous.bytes))) throw invalid();
      sections.push(section);
    }
    const mapped = (address: number): { offset: number; available: number } => {
      if (!Number.isSafeInteger(address) || address <= 0 || address >= 0x1_0000_0000) throw invalid();
      if (address < headers) return { offset: address, available: headers - address };
      const section = sections.find((value) => address >= value.address && address - value.address < value.bytes);
      if (section === undefined) throw invalid();
      const delta = address - section.address;
      return { offset: section.offset + delta, available: section.bytes - delta };
    };
    const rva = async (address: number, bytes: number): Promise<Buffer> => {
      const value = mapped(address);
      if (bytes > value.available) throw invalid();
      return read(value.offset, bytes);
    };
    const imports = new Map<string, string>();
    let descriptors = 0;
    for (const [directory, stride, nameOffset] of [[1, 20, 12], [13, 32, 4]] as const) {
      if (directory >= directories) continue;
      const address = optional.readUInt32LE(112 + directory * 8), bytes = optional.readUInt32LE(116 + directory * 8);
      if (address === 0 && bytes === 0) continue;
      if (address === 0 || bytes < stride || bytes > 8 * 1024 ** 2) throw invalid();
      // Validate the directory's complete initialized extent, without reading
      // all its symbol/IAT bytes or manufacturing imports from adjacent data.
      if (mapped(address).available < bytes) throw invalid();
      let terminated = false;
      for (let offset = 0; offset + stride <= bytes; offset += stride) {
        const entry = await rva(address + offset, stride);
        if (entry.every((byte) => byte === 0)) { terminated = true; break; }
        if (++descriptors > MAX_IMPORTS || directory === 13 && entry.readUInt32LE(0) !== 1 ||
            entry.readUInt32LE(directory === 13 ? 12 : 16) === 0) throw invalid();
        const name = mapped(entry.readUInt32LE(nameOffset));
        const encoded = await read(name.offset, Math.min(129, name.available));
        const end = encoded.indexOf(0);
        if (end < 1 || end > 128) throw invalid();
        const value = encoded.subarray(0, end).toString("ascii");
        // toString('ascii') masks high bits: validate the original bytes too.
        if (encoded.subarray(0, end).some((byte) => byte > 127) || !/^[A-Za-z0-9_.+-]+\.dll$/iu.test(value)) throw invalid();
        if (!imports.has(value.toLowerCase())) imports.set(value.toLowerCase(), value);
      }
      if (!terminated) throw invalid();
    }
    const after = await file.stat();
    if (after.size !== identity.size || after.mtimeMs !== identity.mtimeMs || after.ctimeMs !== identity.ctimeMs) throw invalid();
    return [...imports.values()];
  } finally { await file.close(); }
}

function overlap(a: number, bytes: number, b: number, otherBytes: number): boolean {
  return a < b + otherBytes && b < a + bytes;
}
