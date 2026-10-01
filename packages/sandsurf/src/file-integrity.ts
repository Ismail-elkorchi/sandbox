import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";

/** Hash a held, bounded artifact without allocating its complete contents. */
export async function sha256File(path: string, maximumBytes: number): Promise<string> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) throw new Error("invalid artifact byte bound");
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n ||
      before.size > BigInt(maximumBytes)) throw new Error(`${path} is not a bounded regular artifact`);
  const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const held = await file.stat({ bigint: true });
    if (held.dev !== before.dev || held.ino !== before.ino || held.size !== before.size ||
        held.mtimeNs !== before.mtimeNs || held.ctimeNs !== before.ctimeNs) {
      throw new Error(`${path} changed before artifact verification`);
    }
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let bytes = 0;
    for (;;) {
      const count = (await file.read(buffer, 0, buffer.length, bytes)).bytesRead;
      if (count === 0) break;
      bytes += count;
      if (bytes > maximumBytes) throw new Error(`${path} grew beyond its artifact bound`);
      hash.update(buffer.subarray(0, count));
    }
    const after = await file.stat({ bigint: true });
    const named = await lstat(path, { bigint: true });
    if (BigInt(bytes) !== held.size || after.size !== held.size || after.nlink !== 1n ||
        after.mtimeNs !== held.mtimeNs || after.ctimeNs !== held.ctimeNs ||
        named.dev !== held.dev || named.ino !== held.ino || named.size !== held.size ||
        named.mtimeNs !== held.mtimeNs || named.ctimeNs !== held.ctimeNs || named.nlink !== 1n ||
        named.isSymbolicLink()) {
      throw new Error(`${path} changed during artifact verification`);
    }
    return hash.digest("hex");
  } finally {
    await file.close();
  }
}
