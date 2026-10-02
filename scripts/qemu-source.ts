// The official archive was signature-verified with QEMU's published release
// key CEACC9E15534EBABB82D3FA03353C9CEF108B584. Pin content, not a moving tag.
export const QEMU_SOURCE = Object.freeze({
  version: "11.1.2",
  url: "https://download.qemu.org/qemu-11.1.2.tar.xz",
  bytes: 141815216,
  sha256: "731b5681e4bb18be313231579b8efd0296c5b015fa36dc533874b639ba838016",
});

// The recipe's relative paths remain runnable in the corresponding-source
// tree. One identical tree is shipped for all native QEMU platforms.
export const QEMU_CORRESPONDING_FILES = [
  `qemu-${QEMU_SOURCE.version}.tar.xz`, "COPYING", "COPYING.LIB", "LICENSE",
  "vmm/qemu/sandsurf-entry.c", "vmm/qemu/sandsurf-entry.h",
  "vmm/qemu/sandsurf-whpx.c", "vmm/qemu/sandsurf-qapi.json",
  "vmm/qemu/hvf.entitlements", "scripts/build-qemu.ts", "scripts/qemu-source.ts",
  "scripts/qemu-runtime.ts", "scripts/qemu-dependencies.ts",
] as const;

/** Mechanical hooks in the pinned GPL QEMU source. Keep the privileged Darwin
 * broker out of the VMM, and apply WHPX's separate scheduling property before
 * the partition can execute. No fallback, optional limit or old owner remains
 * in the resulting executable. QEMU keeps its upstream migration blockers. */
export function ownerHooks(main: string, whpx: string, misc: string, schema: string): { main: string; whpx: string; misc: string } {
  if (main.includes("sandsurf_qemu_enter") || whpx.includes("sandsurf_cap") || misc.includes("SandsurfPartitionCounters")) {
    throw new Error("QEMU source already has a native owner");
  }
  const replace = (source: string, before: string, after: string): string => {
    if (source.split(before).length !== 2) throw new Error("pinned QEMU owner hook no longer matches exactly once");
    return source.replace(before, after);
  };
  main = replace(main, '#include "qemu-main.h"', '#include "qemu-main.h"\n#include "../sandsurf-entry.c"');
  main = replace(main, "    qemu_init(argc, argv);", "    argc = sandsurf_qemu_enter(argc, &argv);\n    qemu_init(argc, argv);");
  whpx = replace(whpx, '#include "qemu/osdep.h"', '#include "qemu/osdep.h"\n#include "../../../sandsurf-entry.h"');
  const setup = "    hr = whp_dispatch.WHvSetupPartition(whpx->partition);";
  const limits = `    /* Sandsurf's host process Job does not account for hypervisor scheduling. */
    UINT32 sandsurf_cap = sandsurf_qemu_cpu_cap();
    WHV_PARTITION_PROPERTY sandsurf_requested = {0}, sandsurf_observed = {0};
    UINT32 sandsurf_written = 0;
    if (sandsurf_cap == 0 || sandsurf_cap > 65536) {
        error_report("Sandsurf: missing admitted partition CPU allowance");
        ret = -EINVAL;
        goto error;
    }
    sandsurf_requested.CpuCap = sandsurf_cap;
    hr = whp_dispatch.WHvSetPartitionProperty(whpx->partition,
        WHvPartitionPropertyCodeCpuCap, &sandsurf_requested, sizeof(sandsurf_requested));
    if (FAILED(hr)) {
        error_report("Sandsurf: native partition CPU enforcement rejected, hr=%08lx", hr);
        ret = -EINVAL;
        goto error;
    }
    hr = whp_dispatch.WHvGetPartitionProperty(whpx->partition,
        WHvPartitionPropertyCodeCpuCap, &sandsurf_observed, sizeof(sandsurf_observed),
        &sandsurf_written);
    if (FAILED(hr) || sandsurf_written < sizeof(UINT32) ||
        sandsurf_written > sizeof(sandsurf_observed) || sandsurf_observed.CpuCap != sandsurf_cap) {
        error_report("Sandsurf: native partition CPU enforcement readback differs");
        ret = -EINVAL;
        goto error;
    }

`;
  return { main, whpx: replace(whpx, setup, limits + setup) + '\n#include "../../../sandsurf-whpx.c"\n',
    // Use the existing generated module. A new include would also require a
    // new Meson QAPI module and can silently omit its handlers from linking.
    misc: misc + "\n" + schema };
}
