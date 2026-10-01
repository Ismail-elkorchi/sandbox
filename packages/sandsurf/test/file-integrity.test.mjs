import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { link, mkdtemp, open, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { sha256File } from "../dist/file-integrity.js";

async function fixture(context) {
  const root = await mkdtemp(join(tmpdir(), "sandsurf-integrity-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test("artifact verification streams a large sparse file with bounded buffers", async (context) => {
  const path = join(await fixture(context), "disk");
  const size = 256 * 1024 ** 2;
  const file = await open(path, "wx");
  await file.truncate(size);
  await file.close();
  const hash = createHash("sha256");
  const block = Buffer.alloc(64 * 1024);
  for (let offset = 0; offset < size; offset += block.length) hash.update(block);
  assert.equal(await sha256File(path, size), hash.digest("hex"));
  await assert.rejects(sha256File(path, size - 1), /bounded regular artifact/u);
});

test("artifact verification rejects aliases and invalid bounds", async (context) => {
  const root = await fixture(context);
  const path = join(root, "artifact");
  await writeFile(path, "payload");
  assert.equal(await sha256File(path, 7), createHash("sha256").update("payload").digest("hex"));
  await assert.rejects(sha256File(path, 0), /byte bound/u);
  await assert.rejects(sha256File(root, 100), /regular artifact/u);
  if (process.platform !== "win32") {
    await symlink(path, join(root, "symbolic"));
    await assert.rejects(sha256File(join(root, "symbolic"), 100), /regular artifact/u);
  }
  await link(path, join(root, "hard"));
  await assert.rejects(sha256File(path, 100), /regular artifact/u);
});
