import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { ownerHooks, QEMU_SOURCE } from "../qemu-source.ts";

test("the pinned QEMU hooks cannot accept drift, duplicate owners or omit partition readback", () => {
  assert.equal(QEMU_SOURCE.sha256.length, 64);
  assert.equal(QEMU_SOURCE.bytes, 141815216);
  const main = '#include "qemu-main.h"\n    qemu_init(argc, argv);';
  const whpx = '#include "qemu/osdep.h"\n    hr = whp_dispatch.WHvSetupPartition(whpx->partition);';
  const schema = readFileSync("vmm/qemu/sandsurf-qapi.json", "utf8");
  assert.equal((schema.match(/'if': 'CONFIG_WIN32'/gu) ?? []).length, 2);
  assert.doesNotMatch(schema, /'if': 'CONFIG_WHPX'/u);
  const hooked = ownerHooks(main, whpx, "# pinned misc schema", schema);
  assert.match(hooked.main, /sandsurf_qemu_enter\(argc, &argv\);\n    qemu_init/u);
  assert.ok(hooked.whpx.indexOf("WHvSetPartitionProperty") < hooked.whpx.indexOf("WHvSetupPartition"));
  assert.ok(hooked.whpx.indexOf("WHvGetPartitionProperty") < hooked.whpx.indexOf("WHvSetupPartition"));
  assert.match(hooked.whpx, /sandsurf_observed.CpuCap != sandsurf_cap/u);
  assert.match(hooked.whpx, /sandsurf-whpx\.c/u);
  assert.match(hooked.whpx, /#include "\.\.\/\.\.\/\.\.\/sandsurf-entry\.h"/u);
  assert.doesNotMatch(hooked.whpx, /extern uint32_t sandsurf_qemu_cpu_cap/u);
  assert.match(hooked.misc, /query-sandsurf-partition-counters/u);
  assert.ok(hooked.misc.endsWith(schema));
  assert.throws(() => ownerHooks(main, whpx, hooked.misc, schema));
  for (const invalid of ["", whpx + whpx, hooked.whpx]) assert.throws(() => ownerHooks(main, invalid, "", schema));
  assert.throws(() => ownerHooks(hooked.main, whpx, "", schema));
});

test("the actual Windows QEMU entry rejects omitted or malformed caps before delegating arguments", { skip: process.platform !== "linux" }, async () => {
  const scratch = await mkdtemp(resolve(tmpdir(), "sandsurf-qemu-entry-"));
  try {
    // This only compiles/tests the portable argv gate, not WHPX or hardware.
    const fixture = resolve(scratch, "entry.c");
    await writeFile(fixture, '#include <stdio.h>\n#include "sandsurf-entry.h"\nint main(int argc, char **argv) { argc = sandsurf_qemu_enter(argc, &argv); printf("%u %d\\n", sandsurf_qemu_cpu_cap(), argc); for (int i=1;i<argc;i++) puts(argv[i]); return argv[argc] != NULL; }\n');
    const executable = resolve(scratch, "entry");
    execFileSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-D_WIN32",
      "-I", resolve("vmm/qemu"), fixture, resolve("vmm/qemu/sandsurf-entry.c"), "-o", executable]);
    const valid = spawnSync(executable, ["--sandsurf-cpu-cap", "49152", "-accel", "whpx"], { encoding: "utf8" });
    assert.equal(valid.status, 0);
    assert.equal(valid.stdout, "49152 3\n-accel\nwhpx\n");
    for (const args of [[], ["-accel", "whpx"], ...["0", "65537", "-1", "1x", " 1", "+1", "999999999", ""].map((value) => ["--sandsurf-cpu-cap", value, "-S"])]) {
      const child = spawnSync(executable, args, { encoding: "utf8" });
      assert.equal(child.status, 70);
      assert.equal(child.stdout, "");
    }
    const source = await readFile("vmm/qemu/sandsurf-entry.c", "utf8");
    assert.match(source, /sandbox_init\(profile, 0, &error\)/u);
    assert.match(source, /--sandsurf-seatbelt/u);
    assert.doesNotMatch(source, /sandbox_init\("/u);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});
