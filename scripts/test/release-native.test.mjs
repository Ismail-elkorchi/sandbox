import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { link, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { QEMU_CORRESPONDING_FILES } from "../qemu-source.ts";
import { qemuRequiredInputs } from "../qemu-runtime.ts";
import test from "node:test";
import { assembleNativeRelease, releasePlatforms } from "../assemble-release-native.ts";

const payloads = {
  "linux-x64": ["sandsurf-host-linux-x64", "firecracker-v1.17.0-x86_64", "firecracker-LICENSE", "firecracker-NOTICE", "firecracker-THIRD-PARTY", "network-boundary.nft", "sandsurf-network.service"],
  "linux-arm64": ["sandsurf-host-linux-arm64", "firecracker-v1.17.0-aarch64", "firecracker-LICENSE", "firecracker-NOTICE", "firecracker-THIRD-PARTY", "network-boundary.nft", "sandsurf-network.service"],
  "macos-x64": ["sandsurf-host-macos-x64", "sandsurf-resource-broker", "qemu-build.json", ...qemuRequiredInputs("macos-x64"), "lib/libglib.dylib"],
  "macos-arm64": ["sandsurf-host-macos-arm64", "sandsurf-resource-broker", "qemu-build.json", ...qemuRequiredInputs("macos-arm64"), "lib/libglib.dylib"],
  "windows-x64": ["sandsurf-host-windows-x64.exe", "qemu-build.json", ...qemuRequiredInputs("windows-x64"), "libglib.dll"],
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
      await mkdir(dirname(join(artifact, platform, name)), { recursive: true });
      await writeFile(join(artifact, platform, name), bytes);
      files[`${platform}/${name}`] = createHash("sha256").update(bytes).digest("hex");
    }
    if (!platform.startsWith("linux-")) {
      const runtime = Object.fromEntries(Object.entries(files).filter(([key]) =>
        !/\/(?:sandsurf-host-|sandsurf-resource-broker$|qemu-build\.json$)/u.test(key))
        .map(([key, digest]) => [key.slice(platform.length + 1), digest]));
      const bytes = Buffer.from(JSON.stringify({ formatVersion: 1, architecture: platform.endsWith("arm64") ? "arm64" : "amd64",
        qemuVersion: "11.1.2", files: runtime }));
      await writeFile(join(artifact, platform, "qemu-runtime.json"), bytes);
      files[`${platform}/qemu-runtime.json`] = createHash("sha256").update(bytes).digest("hex");
      const binary = platform.startsWith("windows-") ? "libglib.dll" : "lib/libglib.dylib";
      const manager = platform.startsWith("windows-") ? "msys2" : "homebrew";
      const sourceNames = manager === "msys2" ? ["installed-package.txt", "glib.src.tar.zst", "glib.src.tar.zst.sig"]
        : ["formula.rb", "install-receipt.json", "glib.tar.xz"];
      const materials = {};
      for (const name of sourceNames) {
        const bytes = Buffer.from(`glib source:${name}`);
        const path = join(artifact, platform, "qemu-dependencies/glib", name);
        await mkdir(dirname(path), { recursive: true }); await writeFile(path, bytes);
        materials[name] = createHash("sha256").update(bytes).digest("hex");
        files[`${platform}/qemu-dependencies/glib/${name}`] = materials[name];
      }
      const dependencyBytes = Buffer.from(JSON.stringify({ formatVersion: 1, components: [{
        manager, name: "glib", version: "2.90.0", license: "LGPL-2.1-or-later",
        binaries: { [binary]: { inputSha256: runtime[binary], sha256: runtime[binary] } }, materials }] }));
      await writeFile(join(artifact, platform, "qemu-dependencies.json"), dependencyBytes);
      files[`${platform}/qemu-dependencies.json`] = createHash("sha256").update(dependencyBytes).digest("hex");
      for (const name of QEMU_CORRESPONDING_FILES) {
        const bytes = Buffer.from(`common QEMU corresponding source:${name}`);
        const path = join(artifact, "qemu-source", name);
        await mkdir(dirname(path), { recursive: true }); await writeFile(path, bytes);
        files[`qemu-source/${name}`] = createHash("sha256").update(bytes).digest("hex");
      }
    }
    await writeFile(join(artifact, "manifest.json"), JSON.stringify({ formatVersion: 1, buildId: "sandsurf-native-1.0.0", files }));
  }
  return { root, staging, destination,
    artifact: (platform) => join(staging, `runtime-${platform}`),
    payload: (platform, name) => join(staging, `runtime-${platform}`, platform, name) };
}

test("release assembly publishes exactly five verified platforms and preserves previous outputs", async (context) => {
  const f = await fixture(context);
  const backup = await assembleNativeRelease(f.staging, f.destination);
  assert.equal(await readFile(join(backup, "obsolete-binary"), "utf8"), "previous checkout");
  assert.deepEqual((await readdir(f.destination)).sort(), ["manifest.json", "qemu-source", ...releasePlatforms].sort());
  const manifest = JSON.parse(await readFile(join(f.destination, "manifest.json"), "utf8"));
  assert.equal(Object.keys(manifest.files).length,
    Object.values(payloads).reduce((count, names) => count + names.length, 0) + 3 + 12 + QEMU_CORRESPONDING_FILES.length);
  for (const [key, digest] of Object.entries(manifest.files)) {
    assert.equal(createHash("sha256").update(await readFile(join(f.destination, key))).digest("hex"), digest);
    if (process.platform !== "win32") {
      const name = key.slice(key.indexOf("/") + 1);
      assert.equal((await stat(join(f.destination, key))).mode & 0o777,
        !key.startsWith("qemu-source/") && (name.startsWith("sandsurf-") || name.startsWith("firecracker-v") || name.startsWith("lib/")) ? 0o755 : 0o644);
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
  ["missing native VM owner", (f) => rm(f.payload("macos-arm64", "sandsurf-qemu-arm64"))],
  ["corrupt dependency", (f) => writeFile(f.payload("windows-x64", "libglib.dll"), "changed DLL")],
  ["unverified loader input", (f) => writeFile(f.payload("macos-x64", "lib/unverified.dylib"), "unverified")],
  ["changed corresponding source", (f) => writeFile(join(f.artifact("windows-x64"), "qemu-source", "scripts/build-qemu.ts"), "unreviewed recipe")],
  ["missing library sources", (f) => rm(f.payload("macos-arm64", "qemu-dependencies/glib/glib.tar.xz"))],
  ["changed library source bytes", (f) => writeFile(f.payload("windows-x64", "qemu-dependencies/glib/glib.src.tar.zst"), "changed source")],
  ["missing native resource broker", (f) => rm(f.payload("macos-arm64", "sandsurf-resource-broker"))],
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
