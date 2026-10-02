// Empty hardware handle probe only; no guest, memory or disks are attached.
// This is not qualification of Sandsurf's QEMU owner or containment.
#if defined(__aarch64__)
#include <Hypervisor/Hypervisor.h>
#else
#include <Hypervisor/hv.h>
#endif
#include <stdio.h>

int main(void)
{
#if defined(__aarch64__)
    hv_return_t created = hv_vm_create(NULL);
#else
    hv_return_t created = hv_vm_create(HV_VM_DEFAULT);
#endif
    hv_return_t destroyed = created == HV_SUCCESS ? hv_vm_destroy() : created;
    printf("{\"engine\":\"qemu-hvf\",\"checks\":["
           "{\"id\":\"hvf-native-handle\",\"passed\":%s,\"result\":%u},"
           "{\"id\":\"hvf-handle-release\",\"passed\":%s}]}\n",
           created == HV_SUCCESS ? "true" : "false", (unsigned)created,
           created == HV_SUCCESS && destroyed == HV_SUCCESS ? "true" : "false");
    return 0;
}
