import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { hydrateImageSources, packImageSources, writeImageIndex } from "../image-sources.ts";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function fixture(context) {
  const root = await mkdtemp(join(tmpdir(), "sandsurf-image-source-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const roots = { images: join(root, "images"), sources: join(root, "sources") };
  const directory = join(roots.images, "development-x64");
  await mkdir(directory, { recursive: true });
  const disks = { "system.ext4": Buffer.from("raw disk"), "system.vhdx": Buffer.from("Windows disk") };
  for (const [name, bytes] of Object.entries(disks)) await writeFile(join(directory, name), bytes);
  const manifest = {
    formatVersion: 1, architecture: "x64", bootBundle: {},
    system: { rootfs: { path: "system.ext4", sha256: digest(disks["system.ext4"]) } },
    platformArtifacts: { windowsX64: { system: { path: "system.vhdx", sha256: digest(disks["system.vhdx"]) } } },
  };
  await writeFile(join(directory, "manifest.json"), JSON.stringify(manifest));
  await writeImageIndex(roots.images, ["x64"]);
  return { roots, directory, disks, manifest };
}

test("ext4 and VHDX sources hydrate to complete digest-verified readonly bytes", async (context) => {
  const f = await fixture(context);
  await packImageSources("x64", f.roots);
  for (const name of Object.keys(f.disks)) {
    assert.ok((await stat(join(f.roots.sources, "development-x64", `${name}.gz`))).size > 0);
    assert.deepEqual(await readFile(join(f.directory, `${name}.gz`)), await readFile(join(f.roots.sources, "development-x64", `${name}.gz`)));
    await rm(join(f.directory, name));
  }
  await hydrateImageSources(f.roots);
  const published = new Map();
  for (const [name, bytes] of Object.entries(f.disks)) {
    assert.deepEqual(await readFile(join(f.directory, name)), bytes);
    if (process.platform !== "win32") assert.equal((await stat(join(f.directory, name))).mode & 0o777, 0o444);
    published.set(name, await stat(join(f.directory, `${name}.gz`), { bigint: true }));
  }
  await hydrateImageSources(f.roots);
  for (const [name, before] of published) {
    const after = await stat(join(f.directory, `${name}.gz`), { bigint: true });
    assert.equal(after.ino, before.ino);
    assert.equal(after.mtimeNs, before.mtimeNs);
    assert.equal(after.nlink, 1n);
  }
});

test("hydration refuses to replace a corrupt published transport", async (context) => {
  const f = await fixture(context);
  await packImageSources("x64", f.roots);
  const path = join(f.directory, "system.ext4.gz");
  await chmod(path, 0o600);
  await writeFile(path, "invalid immutable transport");
  const before = await stat(path, { bigint: true });
  await assert.rejects(hydrateImageSources(f.roots));
  assert.equal(await readFile(path, "utf8"), "invalid immutable transport");
  assert.equal((await stat(path, { bigint: true })).ino, before.ino);
});

test("explicit image production replaces readonly build transports for a new identity", async (context) => {
  const f = await fixture(context);
  await packImageSources("x64", f.roots);
  const next = Buffer.from("a newly constructed Linux system disk");
  await writeFile(join(f.directory, "system.ext4"), next);
  f.manifest.system.rootfs.sha256 = digest(next);
  await writeFile(join(f.directory, "manifest.json"), JSON.stringify(f.manifest));
  await writeImageIndex(f.roots.images, ["x64"]);
  await packImageSources("x64", f.roots);
  await rm(join(f.directory, "system.ext4"));
  await hydrateImageSources(f.roots);
  assert.deepEqual(await readFile(join(f.directory, "system.ext4")), next);
});

test("hydration rejects a changed manifest before interpreting disk paths", async (context) => {
  const f = await fixture(context);
  await packImageSources("x64", f.roots);
  await writeFile(join(f.directory, "manifest.json"), JSON.stringify({ ...f.manifest, system: {} }));
  await assert.rejects(hydrateImageSources(f.roots), /differs from the image index/u);
});

test("image compression rejects platform disk traversal and mislabeled formats", async (context) => {
  const f = await fixture(context);
  for (const path of ["../system.vhdx", "system.ext4"]) {
    f.manifest.platformArtifacts.windowsX64.system.path = path;
    await writeFile(join(f.directory, "manifest.json"), JSON.stringify(f.manifest));
    await assert.rejects(packImageSources("x64", f.roots), /invalid vhdx artifact identity/u);
  }
});

test("corrupt compressed VHDX never publishes unverified bytes", async (context) => {
  const f = await fixture(context);
  await packImageSources("x64", f.roots);
  await rm(join(f.directory, "system.vhdx"));
  await writeFile(join(f.roots.sources, "development-x64/system.vhdx.gz"), "not gzip");
  await assert.rejects(hydrateImageSources(f.roots));
  await assert.rejects(stat(join(f.directory, "system.vhdx")), { code: "ENOENT" });
  assert.deepEqual(await readFile(join(f.directory, "system.ext4")), f.disks["system.ext4"]);
});

test("hydration refuses corrupt existing disk data rather than replacing it", async (context) => {
  const f = await fixture(context);
  await packImageSources("x64", f.roots);
  await chmod(join(f.directory, "system.vhdx"), 0o600);
  await writeFile(join(f.directory, "system.vhdx"), "changed");
  await assert.rejects(hydrateImageSources(f.roots), /differs from its image manifest/u);
  assert.equal(await readFile(join(f.directory, "system.vhdx"), "utf8"), "changed");
});
