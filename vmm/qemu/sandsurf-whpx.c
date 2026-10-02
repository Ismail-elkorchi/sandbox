/* SPDX-License-Identifier: GPL-2.0-or-later
 * Included only in the pinned WHPX implementation. The private QMP endpoint
 * queries this owner's original partition, never a guest-supplied handle/PID.
 */
#include "qapi/qapi-commands-misc.h"

SandsurfPartitionCounters *qmp_query_sandsurf_partition_counters(Error **errp)
{
    typedef HRESULT (WINAPI *RuntimeQuery)(WHV_PARTITION_HANDLE, UINT32,
        WHV_VIRTUAL_PROCESSOR_COUNTER_SET, PVOID, UINT32, UINT32 *);
    HMODULE module = GetModuleHandleW(L"WinHvPlatform.dll");
    RuntimeQuery query = module ? (RuntimeQuery)GetProcAddress(module,
        "WHvGetVirtualProcessorCounters") : NULL;
    struct whpx_state *owner = &whpx_global;
    CPUState *cpu;
    uint64_t runtime = 0, hypervisor = 0;
    uint32_t processors = 0;
    if (!query || !owner->partition || !whpx_enabled()) {
        error_setg(errp, "Sandsurf: native partition counters unavailable");
        return NULL;
    }
    CPU_FOREACH(cpu) {
        WHV_PROCESSOR_RUNTIME_COUNTERS observed = {0};
        UINT32 written = 0;
        if (++processors > 32 || cpu->cpu_index < 0 || cpu->cpu_index >= 32) {
            error_setg(errp, "Sandsurf: native processor inventory exceeds bound");
            return NULL;
        }
        HRESULT status = query(owner->partition, cpu->cpu_index,
            WHvVirtualProcessorCounterSetRuntime, &observed,
            sizeof(observed), &written);
        if (FAILED(status) || written != sizeof(observed) ||
            UINT64_MAX - runtime < observed.TotalRuntime100ns ||
            UINT64_MAX - hypervisor < observed.HypervisorRuntime100ns) {
            error_setg(errp, "Sandsurf: native partition counters failed or overflowed");
            return NULL;
        }
        runtime += observed.TotalRuntime100ns;
        hypervisor += observed.HypervisorRuntime100ns;
    }
    if (processors == 0) {
        error_setg(errp, "Sandsurf: native partition has no virtual processors");
        return NULL;
    }
    SandsurfPartitionCounters *result = g_new0(SandsurfPartitionCounters, 1);
    /* Convert after summing to avoid a rounding loss for every VP. Report the
     * two kernel ledgers independently. Their overlap with Job accounting is
     * not established by this observation and is never blindly summed. */
    result->total_runtime_micros = runtime / 10;
    result->hypervisor_runtime_micros = hypervisor / 10;
    result->virtual_processors = processors;
    return result;
}
