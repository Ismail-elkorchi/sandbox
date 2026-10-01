import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { bundledImageManifestDigest } from "../native-image.ts";

test("native assembly has no default OS for an absent architecture and verifies every declared identity", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "sandsurf-native-image-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const directory = join(root, "development-x64");
  await mkdir(directory);
  const path = join(directory, "manifest.json");
  const bytes = Buffer.from('{"formatVersion":1}');
  await writeFile(path, bytes);
  const digest = createHash("sha256").update(bytes).digest("hex");
  const index = join(root, "manifest.json");
  await writeFile(index, JSON.stringify({ formatVersion: 1, files: { "development-x64/manifest.json": digest } }));
  assert.equal(await bundledImageManifestDigest(root, "x64"), digest);
  assert.equal(await bundledImageManifestDigest(root, "arm64"), undefined);
  await writeFile(path, "changed input");
  await assert.rejects(bundledImageManifestDigest(root, "x64"), /differs/u);
  for (const value of [null, {}, { formatVersion: 2, files: {} }, { formatVersion: 1, files: { "development-arm64/manifest.json": null } }]) {
    await writeFile(index, JSON.stringify(value));
    await assert.rejects(bundledImageManifestDigest(root, "arm64"), /malformed/u);
  }
});
