/* SDK-compiled native boundary: no Rust copies of private Darwin ABI layouts.
 * No destination, executable path, target PID or guest authority is accepted. */
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define SANDSURF_NETWORK_UID 65530

int sandsurf_darwin_network_socket(int family, int type, int protocol)
{
    if (!((family == AF_INET || family == AF_INET6) &&
          ((type == SOCK_STREAM && protocol == IPPROTO_TCP) ||
           (type == SOCK_DGRAM && protocol == IPPROTO_UDP)))) {
        errno = EINVAL;
        return -1;
    }
    /* This tiny synchronous section runs no callbacks, allocations, Rust or
     * arbitrary workload while impersonating. Other threads retain root.
     * Failure to restore is fatal, never continuation under a wrong identity. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (pthread_setugid_np(SANDSURF_NETWORK_UID, SANDSURF_NETWORK_UID) != 0) return -1;
    int descriptor = socket(family, type, protocol);
    int saved = errno;
    if (pthread_setugid_np((uid_t)-1, (gid_t)-1) != 0) _exit(70);
#pragma clang diagnostic pop
    errno = saved;
    return descriptor;
}

int sandsurf_darwin_peer_identity(int socket, uint32_t identity[8])
{
    audit_token_t token = {0};
    socklen_t length = sizeof(token);
    _Static_assert(sizeof(token) == 8 * sizeof(uint32_t), "audit token envelope");
    if (getsockopt(socket, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) != 0) return -1;
    if (length != sizeof(token)) { errno = EINVAL; return -1; }
    memcpy(identity, &token, sizeof(token));
    return 0;
}

int sandsurf_darwin_peer_alive(const uint32_t identity[8])
{
    audit_token_t token;
    memcpy(&token, identity, sizeof(token));
    char path[PROC_PIDPATHINFO_MAXSIZE];
    /* This API checks the original audit-token idversion in the kernel. It is
     * an observation, not adoption of a PID discovered after peer exit. */
    return proc_pidpath_audittoken(&token, path, sizeof(path)) > 0 ? 0 : -1;
}

int sandsurf_darwin_running_executable(void)
{
    struct proc_regionwithpathinfo region = {0};
    uint64_t address = (uintptr_t)&sandsurf_darwin_running_executable;
    if (proc_pidinfo(getpid(), PROC_PIDREGIONPATHINFO, address,
                     &region, sizeof(region)) != (int)sizeof(region)) return -1;
    int descriptor = open(region.prp_vip.vip_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) return -1;
    struct stat file;
    if (fstat(descriptor, &file) != 0 || !S_ISREG(file.st_mode) ||
        file.st_uid != 0 || (file.st_mode & 0022) != 0 ||
        file.st_ino != region.prp_vip.vip_vi.vi_stat.vst_ino ||
        (uint32_t)file.st_dev != region.prp_vip.vip_vi.vi_stat.vst_dev) {
        close(descriptor);
        errno = EACCES;
        return -1;
    }
    return descriptor;
}
