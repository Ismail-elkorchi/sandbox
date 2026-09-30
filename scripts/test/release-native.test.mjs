import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { link, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { assembleNativeRelease, releasePlatforms } from "../assemble-release-native.ts";

const payloads = {
  "linux-x64": ["sandsurf-host-linux-x64", "firecracker-v1.17.0-x86_64", "firecracker-LICENSE", "firecracker-NOTICE", "firecracker-THIRD-PARTY"],
  "linux-arm64": ["sandsurf-host-linux-arm64", "firecracker-v1.17.0-aarch64", "firecracker-LICENSE", "firecracker-NOTICE", "firecracker-THIRD-PARTY"],
  "macos-x64": ["sandsurf-host-macos-x64", "sandsurf-vz-helper-x64"],
  "macos-arm64": ["sandsurf-host-macos-arm64", "sandsurf-vz-helper-arm64"],
  "windows-x64": ["sandsurf-host-windows-x64.exe"],
};

async function fixture(context) {
  const root = await mkdtemp(join(tmpdir(), "sandsurf-native-release-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const staging = join(root, "inputs");
  const destination = join(root, "native");
  await mkdir(staging); await mkdir(destination);
  await writeFile(join(destination, "obsolete-binary"), "previous checkout");
  for (const platform of releasePlatforms) {
    const artifact = join(staging, `runtime-${platform}`);
    await mkdir(join(artifact, platform), { recursive: true });
    const files = {};
    for (const name of payloads[platform]) {
      const bytes = Buffer.from(`${platform}:${name}`);
      await writeFile(join(artifact, platform, name), bytes);
      files[`${platform}/${name}`] = createHash("sha256").update(bytes).digest("hex");
    }
    await writeFile(join(artifact, "manifest.json"), JSON.stringify({ formatVersion: 1, buildId: "sandsurf-native-0.1.0", files }));
  }
  return { root, staging, destination,
    artifact: (platform) => join(staging, `runtime-${platform}`),
    payload: (platform, name) => join(staging, `runtime-${platform}`, platform, name) };
}

test("release assembly publishes exactly five verified platforms and preserves previous outputs", async (context) => {
  const f = await fixture(context);
  const backup = await assembleNativeRelease(f.staging, f.destination);
  assert.equal(await readFile(join(backup, "obsolete-binary"), "utf8"), "previous checkout");
  assert.deepEqual((await readdir(f.destination)).sort(), ["manifest.json", ...releasePlatforms].sort());
  const manifest = JSON.parse(await readFile(join(f.destination, "manifest.json"), "utf8"));
  assert.equal(Object.keys(manifest.files).length, 15);
  for (const [key, digest] of Object.entries(manifest.files)) {
    assert.equal(createHash("sha256").update(await readFile(join(f.destination, key))).digest("hex"), digest);
    if (process.platform !== "win32") {
      const name = key.split("/")[1];
      assert.equal((await stat(join(f.destination, key))).mode & 0o777,
        name.startsWith("sandsurf-") || name.startsWith("firecracker-v") ? 0o755 : 0o644);
    }
  }
  const name = payloads["linux-x64"][0];
  const original = await readFile(join(f.destination, "linux-x64", name));
  await writeFile(f.payload("linux-x64", name), "modified build input");
  assert.deepEqual(await readFile(join(f.destination, "linux-x64", name)), original);
});

for (const [name, corrupt] of [
  ["missing platform", (f) => rm(f.artifact("windows-x64"), { recursive: true })],
  ["undeclared platform", (f) => mkdir(join(f.staging, "runtime-windows-arm64"))],
  ["missing build manifest", (f) => rm(join(f.artifact("linux-x64"), "manifest.json"))],
  ["changed payload bytes", (f) => writeFile(f.payload("linux-x64", payloads["linux-x64"][0]), "unapproved binary")],
  ["missing native helper", (f) => rm(f.payload("macos-arm64", "sandsurf-vz-helper-arm64"))],
  ["obsolete payload", (f) => writeFile(f.payload("linux-x64", "sandbox-launcher"), "obsolete")],
  ["oversized manifest", (f) => writeFile(join(f.artifact("linux-x64"), "manifest.json"), Buffer.alloc(1024 ** 2 + 1))],
  ["oversized payload", (f) => truncate(f.payload("linux-x64", payloads["linux-x64"][0]), 512 * 1024 ** 2 + 1)],
  ["shared payload identity", async (f) => {
    const path = f.payload("linux-x64", payloads["linux-x64"][0]);
    await rm(path); await link(join(f.destination, "obsolete-binary"), path);
  }],
]) {
  test(`release assembly refuses ${name} without changing existing outputs`, async (context) => {
    const f = await fixture(context);
    await corrupt(f);
    await assert.rejects(assembleNativeRelease(f.staging, f.destination));
    assert.equal(await readFile(join(f.destination, "obsolete-binary"), "utf8"), "previous checkout");
    assert.deepEqual(await readdir(f.destination), ["obsolete-binary"]);
    assert.equal((await readdir(f.root)).some((entry) => entry.startsWith(".native-release-")), false);
  });
}

test("release assembly refuses a linked platform directory", { skip: process.platform === "win32" }, async (context) => {
  const f = await fixture(context);
  const platform = join(f.artifact("linux-x64"), "linux-x64");
  await rm(platform, { recursive: true });
  await symlink(f.destination, platform);
  await assert.rejects(assembleNativeRelease(f.staging, f.destination), /owned artifact directory/u);
  assert.equal(await readFile(join(f.destination, "obsolete-binary"), "utf8"), "previous checkout");
});
