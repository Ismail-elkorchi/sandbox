import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";

test("the actual partition query bounds VP inventory, counter sizes and sums", { skip: process.platform !== "linux" }, async () => {
  const root = await mkdtemp(resolve(tmpdir(), "sandsurf-partition-counter-"));
  try {
    await mkdir(resolve(root, "qapi"));
    await writeFile(resolve(root, "qapi/qapi-commands-misc.h"), `
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#define WINAPI
typedef int32_t HRESULT;
typedef uint32_t UINT32;
typedef void *PVOID;
typedef void *HMODULE;
typedef void *WHV_PARTITION_HANDLE;
typedef int WHV_VIRTUAL_PROCESSOR_COUNTER_SET;
#define WHvVirtualProcessorCounterSetRuntime 0
#define FAILED(value) ((value) < 0)
typedef struct { uint64_t TotalRuntime100ns, HypervisorRuntime100ns; } WHV_PROCESSOR_RUNTIME_COUNTERS;
typedef struct { uint64_t total_runtime_micros, hypervisor_runtime_micros; uint32_t virtual_processors; } SandsurfPartitionCounters;
typedef struct { bool failed; } Error;
typedef struct { int cpu_index; } CPUState;
struct whpx_state { WHV_PARTITION_HANDLE partition; };
static struct whpx_state whpx_global;
static CPUState cpus[33];
static uint32_t count;
static int scenario;
static bool whpx_enabled(void) { return scenario != 1; }
#define CPU_FOREACH(cpu) for (cpu = cpus; cpu < cpus + count; cpu++)
#define g_new0(type, number) ((type *)calloc(number, sizeof(type)))
static void error_setg(Error **error, const char *message) { (void)message; (*error)->failed = true; }
static HMODULE GetModuleHandleW(const void *name) { (void)name; return scenario == 2 ? NULL : (HMODULE)1; }
static HRESULT mock_query(WHV_PARTITION_HANDLE owner, UINT32 cpu, WHV_VIRTUAL_PROCESSOR_COUNTER_SET kind, PVOID bytes, UINT32 size, UINT32 *written) {
    if (owner != (WHV_PARTITION_HANDLE)1 || kind != 0 || size != sizeof(WHV_PROCESSOR_RUNTIME_COUNTERS) || cpu >= 32) abort();
    WHV_PROCESSOR_RUNTIME_COUNTERS *value = bytes;
    value->TotalRuntime100ns = scenario == 6 ? (cpu == 0 ? UINT64_MAX : 1) : 11;
    value->HypervisorRuntime100ns = scenario == 7 ? (cpu == 0 ? UINT64_MAX : 1) : 4;
    *written = size + (scenario == 5 ? 1 : 0);
    return scenario == 4 ? -1 : 0;
}
static void (*GetProcAddress(HMODULE module, const char *name))(void) {
    if (module != (HMODULE)1 || strcmp(name, "WHvGetVirtualProcessorCounters")) abort();
    return scenario == 3 ? NULL : (void (*)(void))mock_query;
}
`);
    const source = resolve("vmm/qemu/sandsurf-whpx.c");
    await writeFile(resolve(root, "fixture.c"), `#include <stdio.h>\n#include "${source}"\n
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  scenario = atoi(argv[1]); count = scenario == 8 ? 0 : scenario == 9 ? 33 : 8;
  for (uint32_t index = 0; index < 33; index++) cpus[index].cpu_index = index;
  if (scenario == 10) cpus[0].cpu_index = -1;
  if (scenario == 11) cpus[0].cpu_index = 32;
  whpx_global.partition = scenario == 12 ? NULL : (WHV_PARTITION_HANDLE)1;
  Error record = {0}, *error = &record;
  SandsurfPartitionCounters *value = qmp_query_sandsurf_partition_counters(&error);
  if (scenario) { if (value || !record.failed) return 3; }
  else { if (!value || record.failed || value->total_runtime_micros != 8 || value->hypervisor_runtime_micros != 3 || value->virtual_processors != 8) return 4; free(value); }
  return 0;
}
`);
    const executable = resolve(root, "fixture");
    execFileSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-cast-function-type", "-I", root,
      resolve(root, "fixture.c"), "-o", executable]);
    for (let scenario = 0; scenario <= 12; scenario++) {
      const result = spawnSync(executable, [String(scenario)], { encoding: "utf8" });
      assert.equal(result.status, 0, `counter scenario ${scenario}: ${result.stderr}`);
    }
    const qapi = await readFile("vmm/qemu/sandsurf-qapi.json", "utf8");
    assert.match(qapi, /'if': 'CONFIG_WIN32'/u);
    assert.doesNotMatch(qapi, /'if': 'CONFIG_WHPX'/u);
    assert.match(qapi, /'query-sandsurf-partition-counters'/u);
    assert.doesNotMatch(qapi, /'pid'|'handle'|'partition-id'/u);
  } finally { await rm(root, { recursive: true, force: true }); }
});
