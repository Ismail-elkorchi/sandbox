import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtemp, mkdir, open, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  assertNativeTarget, createPackageArchive, digestFile, parseArguments,
  parseSelectedPackages, prepare, REQUIRED_PACKAGES, validatePackageLock,
} from "../prepare-alpine-inputs.ts";

const script = fileURLToPath(new URL("../prepare-alpine-inputs.ts", import.meta.url));
const closure = [...REQUIRED_PACKAGES, "musl", "busybox", "apk-tools"]
  .map((name) => `${name}=1.2.3-r0`).sort().join("\n") + "\n";

test("CLI requires explicit architecture, absolute bounded paths, and unique known options", () => {
  assert.deepEqual(parseArguments(["--architecture", "x64", "--output", "/var/tmp/prepared"]), {
    architecture: "x64", output: "/var/tmp/prepared", temporaryDirectory: "/var/tmp",
  });
  for (const args of [
    ["--output", "/var/tmp/prepared"],
    ["--architecture", "x86_64", "--output", "/var/tmp/prepared"],
    ["--architecture", "x64", "--output", "relative"],
    ["--architecture", "x64", "--output", "/var/tmp/unsafe\npath"],
    ["--architecture", "x64", "--output", "/var/tmp/prepared", "--architecture", "arm64"],
    ["--architecture", "x64", "--output", "/var/tmp/prepared", "--allow-untrusted", "yes"],
    ["--architecture", "x64", "--output"],
  ]) assert.throws(() => parseArguments(args));
  const result = spawnSync(process.execPath, [script, "--output", "/var/tmp/prepared"], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /architecture.*required/u);
});

test("cross-architecture execution and non-Linux hosts fail explicitly", () => {
  assert.doesNotThrow(() => assertNativeTarget("x64", "linux", "x64"));
  assert.doesNotThrow(() => assertNativeTarget("arm64", "linux", "arm64"));
  assert.throws(() => assertNativeTarget("arm64", "linux", "x64"), /unqualified and unsupported/u);
  assert.throws(() => assertNativeTarget("x64", "darwin", "x64"), /native Linux/u);
});

test("APK selections map only safe local main/community paths to explicit official URLs", () => {
  const packages = parseSelectedPackages(
    "/inputs/community/x86_64/sudo-1.9.17_p2-r1.apk\nfile:///inputs/main/x86_64/alpine-base-3.24.2-r0.apk\n", "x64",
  );
  assert.deepEqual(packages.map((entry) => entry.basename), ["alpine-base-3.24.2-r0.apk", "sudo-1.9.17_p2-r1.apk"]);
  assert.equal(packages[1].url, "https://dl-cdn.alpinelinux.org/alpine/v3.24/community/x86_64/sudo-1.9.17_p2-r1.apk");
  assert.equal(parseSelectedPackages("/inputs/main/aarch64/musl-1.2.6-r2.apk\n", "arm64")[0].repository, "main");
});

test("malformed, ambiguous, oversized and injected solver outputs are rejected", () => {
  for (const line of [
    "https://evil.example/test-1-r0.apk", "/inputs/testing/x86_64/test-1-r0.apk",
    "/inputs/main/aarch64/test-1-r0.apk", "/inputs/main/x86_64/../test-1-r0.apk",
    "/inputs/main/x86_64/test-1-r0.apk?redirect=evil", "/inputs/main/x86_64/%2e%2e.apk",
    "/inputs/main/x86_64/test-1-r0.apk;id", "/inputs/main/x86_64/test-$(id)-1.apk",
    "/inputs/main/x86_64/test-1-r0.apk\r", "/inputs/main/x86_64/test.apk", "",
  ]) assert.throws(() => parseSelectedPackages(`${line}\n`, "x64"));
  const valid = "/inputs/main/x86_64/test-1-r0.apk\n";
  assert.throws(() => parseSelectedPackages(valid.trimEnd(), "x64"), /incomplete/u);
  assert.throws(() => parseSelectedPackages(valid + valid.replace("main", "community"), "x64"), /colliding/u);
  assert.throws(() => parseSelectedPackages(valid.repeat(513), "x64"), /count/u);
  assert.throws(() => parseSelectedPackages("x".repeat(256 * 1024 + 1) + "\n", "x64"), /oversized/u);
});

test("installed lock enforces exact sorted P=V records and the minimum closure", () => {
  assert.equal(validatePackageLock(closure).length, REQUIRED_PACKAGES.length + 3);
  for (const invalid of [
    closure.trimEnd(), closure.replace("alpine-base=1.2.3-r0\n", ""),
    closure + "sudo=1.2.3-r0\n", closure.replace("busybox=1.2.3-r0", "busybox 1.2.3-r0"),
    closure.replace("busybox=1.2.3-r0", "busybox=1.2.3-r0=extra"),
    closure.split("\n").filter(Boolean).reverse().join("\n") + "\n",
    closure.replace("musl=1.2.3-r0", "../musl=1.2.3-r0"),
  ]) assert.throws(() => validatePackageLock(invalid));
});

test("digest checks reject empty, oversized and symlink inputs", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "alpine-input-digest-"));
  try {
    const file = join(temporary, "data"); await writeFile(file, "signed package data");
    const expected = createHash("sha256").update("signed package data").digest("hex");
    assert.deepEqual(await digestFile(file, 1024), { sha256: expected, bytes: 19 });
    await assert.rejects(digestFile(file, 1), /bounded/u);
    const link = join(temporary, "link"); await symlink(file, link);
    await assert.rejects(digestFile(link, 1024), /regular/u);
    await writeFile(file, ""); await assert.rejects(digestFile(file, 1024), /nonempty/u);
  } finally { await rm(temporary, { recursive: true, force: true }); }
});

test("package archive contains only solver-selected bytes at builder cache paths", { skip: process.platform !== "linux" }, async () => {
  const temporary = await mkdtemp(join(tmpdir(), "alpine-input-archive-"));
  try {
    const tree = join(temporary, "tree"); const cache = join(tree, "var/cache/apk");
    await mkdir(cache, { recursive: true });
    await writeFile(join(cache, "test-1-r0.apk"), "opaque fixture bytes");
    await writeFile(join(cache, "unselected-1-r0.apk"), "must not be included");
    const selected = parseSelectedPackages("/inputs/main/x86_64/test-1-r0.apk\n", "x64");
    const archive = join(temporary, "packages.tar.gz");
    await createPackageArchive(tree, archive, selected, temporary);
    assert.equal(execFileSync("/usr/bin/tar", ["-tzf", archive], { encoding: "utf8" }), "var/cache/apk/test-1-r0.apk\n");
    assert.equal(execFileSync("/usr/bin/tar", ["-xOzf", archive, "var/cache/apk/test-1-r0.apk"], { encoding: "utf8" }), "opaque fixture bytes");
    const second = join(temporary, "second.tar.gz");
    await createPackageArchive(tree, second, selected, temporary);
    assert.deepEqual(await readFile(archive), await readFile(second));
    await assert.rejects(createPackageArchive(tree, second, [{ ...selected[0], basename: "../evil.apk" }], temporary), /unsafe/u);
  } finally { await rm(temporary, { recursive: true, force: true }); }
});

test("real native KVM preparation verifies and publishes digest-bound inputs", {
  skip: process.env.SANDSURF_APK_KVM_TEST !== "1", timeout: 900_000,
}, async () => {
  // Explicit opt-in: default tests do not launch VMs or download packages.
  const temporary = await mkdtemp("/var/tmp/alpine-input-kvm-test-");
  const architecture = process.arch;
  assert.ok(architecture === "x64" || architecture === "arm64");
  try {
    const output = join(temporary, "published");
    const environment = await prepare({ architecture, output, temporaryDirectory: temporary,
      ...(process.env.SANDSURF_APK_MINIROOTFS ? { minirootfs: process.env.SANDSURF_APK_MINIROOTFS } : {}),
    });
    assert.equal((await digestFile(environment.SANDSURF_ALPINE_PACKAGES_ARCHIVE, 1024 ** 3)).sha256, environment.SANDSURF_ALPINE_PACKAGES_SHA256);
    assert.equal((await digestFile(environment.SANDSURF_ALPINE_PACKAGE_LOCK, 256 * 1024)).sha256, environment.SANDSURF_ALPINE_PACKAGE_LOCK_SHA256);
    const lock = validatePackageLock(await readFile(environment.SANDSURF_ALPINE_PACKAGE_LOCK, "utf8"));
    const provenance = JSON.parse(await readFile(join(output, "provenance.json"), "utf8"));
    assert.equal(provenance.installedPackages, lock.length);
    assert.equal(provenance.execution.network, false);
    assert.equal(provenance.execution.accelerator, "KVM");
    const members = execFileSync("/usr/bin/tar", ["-tzf", environment.SANDSURF_ALPINE_PACKAGES_ARCHIVE], { encoding: "utf8" }).trim().split("\n");
    assert.deepEqual(members, provenance.packages.map((entry) => `var/cache/apk/${entry.basename}`));
    if (process.env.SANDSURF_APK_MINIROOTFS) {
      // A real signed package must verify with the pinned keys and fail with
      // an empty trust store. Both checks run inside the network-disabled VM.
      const disk = join(temporary, "signature-probe.raw");
      const handle = await open(disk, "wx", 0o600);
      try { await handle.truncate(2 * 1024 ** 3); } finally { await handle.close(); }
      const probe = join(temporary, "signature-probe.sh");
      await writeFile(probe, `#!/bin/sh
set -eu
set -- /var/cache/apk/*.apk
apk --no-network --repositories-file /dev/null verify "$1" > /inputs/trusted
mkdir -p /inputs/empty-keys
if apk --no-network --keys-dir /inputs/empty-keys --repositories-file /dev/null verify "$1" > /inputs/untrusted 2>&1; then
  echo 'signature verification accepted an empty trust store' >&2
  exit 1
fi
cat /inputs/trusted
cat /inputs/untrusted
`);
      const result = execFileSync("/usr/bin/timeout", ["--signal=KILL", "120", "/usr/bin/guestfish",
        "--no-progress-bars", "--format=raw", "-a", disk,
        "set-pgroup", "false", ":", "set-network", "false", ":", "run",
        ":", "mkfs", "ext4", "/dev/sda", ":", "mount-options", "rw", "/dev/sda", "/",
        ":", "tar-in", process.env.SANDSURF_APK_MINIROOTFS, "/", "compress:gzip",
        ":", "tar-in", environment.SANDSURF_ALPINE_PACKAGES_ARCHIVE, "/", "compress:gzip",
        ":", "mkdir-p", "/inputs", ":", "upload", probe, "/inputs/probe.sh",
        ":", "command", "/bin/sh /inputs/probe.sh",
      ], { encoding: "utf8", maxBuffer: 256 * 1024, env: {
        PATH: "/usr/sbin:/usr/bin:/sbin:/bin", TMPDIR: temporary,
        LIBGUESTFS_BACKEND: "direct", LIBGUESTFS_BACKEND_SETTINGS: "force_kvm", LIBGUESTFS_MEMSIZE: "512",
        LIBGUESTFS_HV: `/usr/bin/qemu-system-${architecture === "x64" ? "x86_64" : "aarch64"}`,
      } });
      assert.match(result, /: OK/u);
      assert.match(result, /UNTRUSTED|untrusted|signature/u);
    }
    await assert.rejects(prepare({ architecture, output, temporaryDirectory: temporary }), /already exists/u);
  } finally { await rm(temporary, { recursive: true, force: true }); }
});
