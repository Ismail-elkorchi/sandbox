import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { ownerHooks, windowsDiskHooks, QEMU_SOURCE } from "../qemu-source.ts";

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
    // This compiles the actual gate against an explicit kernel API fixture;
    // Windows CI separately exercises original handles, not this fake ABI.
    await writeFile(resolve(scratch, "windows.h"), `#include <stdint.h>
typedef void *HANDLE;
typedef uint32_t DWORD;
#define INVALID_HANDLE_VALUE ((HANDLE)(uintptr_t)-1)
#define FILE_TYPE_DISK 1
#define HANDLE_FLAG_INHERIT 1
#define ERROR_ACCESS_DENIED 5
#define DUPLICATE_SAME_ACCESS 2
#define FALSE 0
static inline DWORD GetFileType(HANDLE h) { return h == (HANDLE)4 || h == (HANDLE)8 ? FILE_TYPE_DISK : 0; }
static inline int GetHandleInformation(HANDLE h, DWORD *f) { (void)h; *f = HANDLE_FLAG_INHERIT; return 1; }
static inline int SetHandleInformation(HANDLE h, DWORD mask, DWORD flags) { (void)h; return mask == HANDLE_FLAG_INHERIT && flags == 0; }
static inline HANDLE GetCurrentProcess(void) { return (HANDLE)1; }
static inline void SetLastError(DWORD error) { (void)error; }
static inline int DuplicateHandle(HANDLE p, HANDLE h, HANDLE q, HANDLE *copy, DWORD access, int inherit, DWORD flags) {
    (void)p; (void)q; *copy = h; return access == 0 && inherit == 0 && flags == DUPLICATE_SAME_ACCESS;
}
`);
    const fixture = resolve(scratch, "entry.c");
    await writeFile(fixture, '#include <stdio.h>\n#include "windows.h"\n#include "sandsurf-entry.h"\nint main(int argc, char **argv) { argc = sandsurf_qemu_enter(argc, &argv); if (sandsurf_qemu_disk("host-path") != INVALID_HANDLE_VALUE || sandsurf_qemu_disk("sandsurf-disk:0") != (HANDLE)4 || sandsurf_qemu_disk("sandsurf-disk:1") != (HANDLE)8) return 99; printf("%u %d\\n", sandsurf_qemu_cpu_cap(), argc); for (int i=1;i<argc;i++) puts(argv[i]); return argv[argc] != NULL; }\n');
    const executable = resolve(scratch, "entry");
    execFileSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-D_WIN32",
      "-I", scratch, "-I", resolve("vmm/qemu"), fixture, resolve("vmm/qemu/sandsurf-entry.c"), "-o", executable]);
    const handles = ["--sandsurf-disk-handles", "4", "8"];
    const valid = spawnSync(executable, ["--sandsurf-cpu-cap", "49152", "-accel", "whpx", ...handles], { encoding: "utf8" });
    assert.equal(valid.status, 0);
    assert.equal(valid.stdout, "49152 3\n-accel\nwhpx\n");
    for (const args of [[], ["-accel", "whpx"], ["--sandsurf-cpu-cap", "49152", "-S"],
      ...["0", "65537", "-1", "1x", " 1", "+1", "999999999", ""].map((value) => ["--sandsurf-cpu-cap", value, "-S", ...handles]),
      ...["0", "8", "-1", "1x", "18446744073709551616"].map((value) => ["--sandsurf-cpu-cap", "49152", "-S", "--sandsurf-disk-handles", value, "8"])]) {
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

test("Windows raw disk hooks remove path reopening and reject patch drift", () => {
  const source = `#include <winioctl.h>
typedef struct BDRVRawReopenState {
    HANDLE hfile;
} BDRVRawReopenState;
    s->hfile = CreateFile(filename, access_flags,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                          OPEN_EXISTING, overlapped, NULL);
static int64_t coroutine_fn raw_co_get_allocated_file_size(void) { GetCompressedFileSizeA(); }
static int raw_co_create(void) {}
static int raw_reopen_prepare(void) { rs->hfile = CreateFile(); }
static void raw_reopen_commit(void) {}
static QemuOptsList raw_create_opts;
    .bdrv_reopen_commit  = raw_reopen_commit,
    .bdrv_reopen_abort   = raw_reopen_abort,
`;
  const hooked = windowsDiskHooks(source);
  assert.match(hooked, /sandsurf_qemu_disk\(filename\)/u);
  assert.match(hooked, /device access is immutable/u);
  assert.match(hooked, /GetFileInformationByHandleEx\(s->hfile/u);
  assert.doesNotMatch(hooked, /CreateFile|BDRVRawReopenState|raw_reopen_commit|raw_reopen_abort/u);
  assert.throws(() => windowsDiskHooks(hooked));
  assert.throws(() => windowsDiskHooks(source + source));
});
