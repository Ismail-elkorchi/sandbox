import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { imageComponents } from "../image-supply-chain.ts";

const package_ = { name: "sudo", version: "1.0-r0", origin: "sudo", architecture: "noarch",
  license: "custom ISC", buildCommit: "a".repeat(40), packageChecksum: `Q1${"A".repeat(27)}=` };
async function fixture(action) {
  const root = await mkdtemp(join(tmpdir(), "os-supply-chain-"));
  const manifests = [];
  try {
    const files = {};
    for (const architecture of ["x64", "arm64"]) {
      const manifest = { formatVersion: 1, architecture, system: { provenance: {
        kind: "assembled", materials: { "alpine-installed-database": "b".repeat(64) },
        distribution: { kind: "alpine", databaseDigest: "b".repeat(64), packages: [package_] },
      } } };
      const relative = `development-${architecture}/manifest.json`;
      await mkdir(join(root, `development-${architecture}`));
      const bytes = JSON.stringify(manifest); await writeFile(join(root, relative), bytes);
      files[relative] = createHash("sha256").update(bytes).digest("hex");
      manifests.push(manifest);
    }
    await writeFile(join(root, "manifest.json"), JSON.stringify({ formatVersion: 1, files }));
    await action(root, manifests, files);
  } finally { await rm(root, { recursive: true, force: true }); }
}
test("OS package provenance preserves distribution licenses and deduplicates actual noarch ownership", async () => {
  await fixture(async (root) => {
    const values = await imageComponents(root);
    assert.equal(values.length, 1);
    assert.deepEqual(values[0].licenses, [{ license: { name: "custom ISC" } }]);
    assert.equal(values[0].properties.filter((v) => v.name === "sandsurf:machine-image").length, 2);
    assert.ok(values[0].properties.some((v) => v.name === "sandsurf:source-pointer"));
    assert.equal(values[0].hashes, undefined, "an installed-record checksum is not a whole-APK digest");
    assert.ok(!values[0].properties.some((v) => v.name === "sandsurf:corresponding-source"));
  });
});
test("OS inventory cannot be substituted under a packaged image identity", async () => {
  await fixture(async (root) => {
    const path = join(root, "development-x64/manifest.json");
    await writeFile(path, (await readFile(path, "utf8")).replace("custom ISC", "MIT"));
    await assert.rejects(imageComponents(root), /packaged identity/u);
  });
});
test("default OS provenance rejects missing, conflicting and foreign package claims", async () => {
  for (const mutate of [
    (v) => { v.kind = "source-built"; },
    (v) => { delete v.distribution; },
    (v) => { v.materials["alpine-installed-database"] = "c".repeat(64); },
    (v) => { v.distribution.packages = []; },
    (v) => { v.distribution.packages.push(package_); },
    (v) => { v.distribution.packages = [{ ...package_, origin: "../host" }]; },
    (v) => { v.distribution.packages = [{ ...package_, buildCommit: "x".repeat(40) }]; },
    (v) => { v.distribution.packages = [{ ...package_, architecture: "x86_64" }]; },
    (v) => { v.distribution.packages = [{ ...package_, license: "MIT\nGPL" }]; },
  ]) await fixture(async (root, manifests, files) => {
    mutate(manifests[1].system.provenance);
    const bytes = JSON.stringify(manifests[1]); await writeFile(join(root, "development-arm64/manifest.json"), bytes);
    files["development-arm64/manifest.json"] = createHash("sha256").update(bytes).digest("hex");
    await writeFile(join(root, "manifest.json"), JSON.stringify({ formatVersion: 1, files }));
    await assert.rejects(imageComponents(root));
  });
});
