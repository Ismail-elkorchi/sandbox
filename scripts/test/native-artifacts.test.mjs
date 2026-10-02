import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, link, mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { artifactFiles, publishNativePlatform, publishNativeTree } from "../native-artifacts.ts";
import { QEMU_CORRESPONDING_FILES } from "../qemu-source.ts";

async function fixture() {
  const root = await mkdtemp(resolve(tmpdir(), "sandsurf-native-artifacts-"));
  const native = resolve(root, "native");
  await mkdir(native);
  const write = async (base, path, bytes) => {
    const target = resolve(base, path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes);
  };
  const manifest = async (base) => {
    const files = {};
    for (const path of await artifactFiles(base)) {
      if (path !== "manifest.json") files[path] = createHash("sha256").update(await readFile(resolve(base, path))).digest("hex");
    }
    await writeFile(resolve(base, "manifest.json"), JSON.stringify({ formatVersion: 1, buildId: "sandsurf-native-1.0.0", files }));
  };
  return { root, native, write, manifest, cleanup: () => rm(root, { recursive: true, force: true }) };
}

test("a platform build replaces one complete payload and preserves other platform identities", async () => {
  const f = await fixture();
  try {
    await f.write(f.native, "linux-x64/sandsurf-host-linux-x64", "old-x64");
    await f.write(f.native, "linux-x64/no-longer-produced", "obsolete");
    await f.write(f.native, "linux-arm64/sandsurf-host-linux-arm64", "retained-arm64");
    await f.manifest(f.native);
    const payload = resolve(f.root, "payload");
    await f.write(payload, "sandsurf-host-linux-x64", "new-x64");
    await publishNativePlatform(f.native, "linux-x64", payload);
    assert.equal(await readFile(resolve(f.native, "linux-x64/sandsurf-host-linux-x64"), "utf8"), "new-x64");
    assert.equal(await readFile(resolve(f.native, "linux-arm64/sandsurf-host-linux-arm64"), "utf8"), "retained-arm64");
    assert.deepEqual(await readdir(resolve(f.native, "linux-x64")), ["sandsurf-host-linux-x64"]);
    const manifest = JSON.parse(await readFile(resolve(f.native, "manifest.json"), "utf8"));
    assert.deepEqual(Object.keys(manifest.files), ["linux-arm64/sandsurf-host-linux-arm64", "linux-x64/sandsurf-host-linux-x64"]);
  } finally { await f.cleanup(); }
});

test("failed or aliased build inputs never change the published payload", async () => {
  const f = await fixture();
  try {
    await f.write(f.native, "linux-x64/sandsurf-host-linux-x64", "original");
    await f.manifest(f.native);
    const before = await readFile(resolve(f.native, "manifest.json"));
    await assert.rejects(publishNativePlatform(f.native, "linux-x64", resolve(f.root, "missing")));
    const payload = resolve(f.root, "payload");
    await f.write(payload, "worker", "aliased");
    await link(resolve(payload, "worker"), resolve(payload, "second-name"));
    await assert.rejects(publishNativePlatform(f.native, "linux-x64", payload), /exclusive regular/u);
    assert.deepEqual(await readFile(resolve(f.native, "manifest.json")), before);
    assert.equal(await readFile(resolve(f.native, "linux-x64/sandsurf-host-linux-x64"), "utf8"), "original");
  } finally { await f.cleanup(); }
});

test("the runtime artifact root cannot quietly package source or unrelated directories", async () => {
  const f = await fixture();
  try {
    await f.write(f.native, "qemu/source.c", "not a runtime artifact");
    const payload = resolve(f.root, "payload");
    await f.write(payload, "host", "candidate");
    await assert.rejects(publishNativePlatform(f.native, "linux-x64", payload), /non-artifact/u);
    assert.equal(await readFile(resolve(f.native, "qemu/source.c"), "utf8"), "not a runtime artifact");
  } finally { await f.cleanup(); }
});

test("whole-tree publication verifies bytes before moving the previous generation", async () => {
  const f = await fixture();
  try {
    await f.write(f.native, "linux-x64/host", "previous");
    await f.manifest(f.native);
    const staged = resolve(f.root, "staged");
    await f.write(staged, "linux-x64/host", "candidate");
    await f.manifest(staged);
    await f.write(staged, "linux-x64/host", "corrupt");
    await assert.rejects(publishNativeTree(staged, f.native), /failed its digest/u);
    assert.equal(await readFile(resolve(f.native, "linux-x64/host"), "utf8"), "previous");
    await f.manifest(staged);
    const backup = await publishNativeTree(staged, f.native);
    assert.equal(await readFile(resolve(backup, "linux-x64/host"), "utf8"), "previous");
    assert.equal(await readFile(resolve(f.native, "linux-x64/host"), "utf8"), "corrupt");
  } finally { await f.cleanup(); }
});

test("common corresponding source cannot be replaced under an unrelated QEMU platform", async () => {
  const f = await fixture();
  try {
    await f.write(f.native, "macos-arm64/host", "retained Mac");
    const corresponding = resolve(f.root, "source");
    for (const file of QEMU_CORRESPONDING_FILES) {
      await f.write(f.native, `qemu-source/${file}`, `source/${file}`);
      await f.write(corresponding, file, `source/${file}`);
    }
    const payload = resolve(f.root, "payload");
    await f.write(payload, "host", "candidate Windows");
    await publishNativePlatform(f.native, "windows-x64", payload, corresponding);
    const before = await readFile(resolve(f.native, "manifest.json"));
    await f.write(corresponding, "vmm/qemu/sandsurf-entry.c", "changed entry");
    await assert.rejects(publishNativePlatform(f.native, "windows-x64", payload, corresponding), /rebuild all QEMU platforms/u);
    assert.deepEqual(await readFile(resolve(f.native, "manifest.json")), before);
  } finally { await f.cleanup(); }
});

test("concurrent platform owners merge under one OS publication lease", async () => {
  const f = await fixture();
  try {
    const x64 = resolve(f.root, "x64"), arm64 = resolve(f.root, "arm64");
    await f.write(x64, "host", "new x64");
    await f.write(arm64, "host", "new arm64");
    await Promise.all([
      publishNativePlatform(f.native, "linux-x64", x64),
      publishNativePlatform(f.native, "linux-arm64", arm64),
    ]);
    const manifest = JSON.parse(await readFile(resolve(f.native, "manifest.json"), "utf8"));
    assert.deepEqual(Object.keys(manifest.files), ["linux-arm64/host", "linux-x64/host"]);
    assert.equal(await readFile(resolve(f.native, "linux-x64/host"), "utf8"), "new x64");
    assert.equal(await readFile(resolve(f.native, "linux-arm64/host"), "utf8"), "new arm64");
  } finally { await f.cleanup(); }
});

test("ordinary build-directory permissions are not confused with private machine IPC", async () => {
  const f = await fixture();
  try {
    if (process.platform !== "win32") await chmod(f.root, 0o775);
    const payload = resolve(f.root, "payload");
    await f.write(payload, "host", "source-built host");
    await publishNativePlatform(f.native, "linux-x64", payload);
    assert.equal(await readFile(resolve(f.native, "linux-x64/host"), "utf8"), "source-built host");
  } finally { await f.cleanup(); }
});

test("interrupted publication restores the original platform set before the next build", async () => {
  const f = await fixture();
  try {
    await f.write(f.native, "linux-arm64/host", "retained arm64");
    await f.manifest(f.native);
    const staged = resolve(f.root, "interrupted-stage");
    await f.write(staged, "linux-x64/host", "never published");
    await f.manifest(staged);
    const backup = resolve(f.root, `.native-previous-${"1".repeat(32)}`, "native");
    await mkdir(dirname(backup));
    await writeFile(resolve(f.root, ".native-publication.json"), JSON.stringify({
      version: 1, staged, backup,
      manifestDigest: createHash("sha256").update(await readFile(resolve(staged, "manifest.json"))).digest("hex"),
    }), { flag: "wx", mode: 0o600 });
    await rename(f.native, backup);
    const payload = resolve(f.root, "payload");
    await f.write(payload, "host", "new x64");
    await publishNativePlatform(f.native, "linux-x64", payload);
    assert.equal(await readFile(resolve(f.native, "linux-arm64/host"), "utf8"), "retained arm64");
    assert.equal(await readFile(resolve(f.native, "linux-x64/host"), "utf8"), "new x64");
    await assert.rejects(readFile(resolve(f.root, ".native-publication.json")), { code: "ENOENT" });
  } finally { await f.cleanup(); }
});

test("completed interrupted publication verifies the new generation and retains its original bytes", async () => {
  const f = await fixture();
  try {
    await f.write(f.native, "linux-arm64/host", "old arm64");
    await f.manifest(f.native);
    const staged = resolve(f.root, "already-installed-stage");
    await f.write(staged, "linux-arm64/host", "installed arm64");
    await f.manifest(staged);
    const backup = resolve(f.root, `.native-previous-${"2".repeat(32)}`, "native");
    await mkdir(dirname(backup));
    await writeFile(resolve(f.root, ".native-publication.json"), JSON.stringify({
      version: 1, staged, backup,
      manifestDigest: createHash("sha256").update(await readFile(resolve(staged, "manifest.json"))).digest("hex"),
    }), { flag: "wx", mode: 0o600 });
    await rename(f.native, backup);
    await rename(staged, f.native);
    const payload = resolve(f.root, "payload");
    await f.write(payload, "host", "new x64");
    await publishNativePlatform(f.native, "linux-x64", payload);
    assert.equal(await readFile(resolve(f.native, "linux-arm64/host"), "utf8"), "installed arm64");
    assert.equal(await readFile(resolve(backup, "linux-arm64/host"), "utf8"), "old arm64");
  } finally { await f.cleanup(); }
});

test("recovery refuses an unverified installed generation without deleting original evidence", async () => {
  const f = await fixture();
  try {
    await f.write(f.native, "linux-arm64/host", "original");
    await f.manifest(f.native);
    const backup = resolve(f.root, `.native-previous-${"3".repeat(32)}`, "native");
    await mkdir(dirname(backup));
    await rename(f.native, backup);
    await f.write(f.native, "linux-arm64/host", "unexpected");
    await f.manifest(f.native);
    await writeFile(resolve(f.root, ".native-publication.json"), JSON.stringify({
      version: 1, staged: resolve(f.root, "missing-stage"), backup, manifestDigest: "0".repeat(64),
    }), { flag: "wx", mode: 0o600 });
    const payload = resolve(f.root, "payload");
    await f.write(payload, "host", "new x64");
    await assert.rejects(publishNativePlatform(f.native, "linux-x64", payload), /differs from interrupted operation/u);
    assert.equal(await readFile(resolve(backup, "linux-arm64/host"), "utf8"), "original");
    assert.equal(await readFile(resolve(f.native, "linux-arm64/host"), "utf8"), "unexpected");
    await readFile(resolve(f.root, ".native-publication.json"));
  } finally { await f.cleanup(); }
});
