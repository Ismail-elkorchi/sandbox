// Read-only prerequisites; this does not create a VM or qualify containment.
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void) {
    int fd = open("/dev/kvm", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    int error = fd < 0 ? errno : 0;
    int version = fd < 0 ? -1 : ioctl(fd, KVM_GET_API_VERSION, 0);
    if (fd >= 0 && version < 0) error = errno;
    int memory = fd < 0 ? -1 : ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
    if (fd >= 0) close(fd);
    printf("{\"engine\":\"firecracker\",\"checks\":["
           "{\"id\":\"kvm-api\",\"passed\":%s,\"version\":%d,\"errno\":%d},"
           "{\"id\":\"kvm-user-memory\",\"passed\":%s},"
           "{\"id\":\"cgroup-v2-present\",\"passed\":%s}]}\n",
           version == KVM_API_VERSION ? "true" : "false", version, error,
           memory > 0 ? "true" : "false",
           access("/sys/fs/cgroup/cgroup.controllers", R_OK) == 0 ? "true" : "false");
    return 0;
}
