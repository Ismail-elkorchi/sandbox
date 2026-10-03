/* SPDX-License-Identifier: GPL-2.0-or-later
 * Native entry gate for the separately distributed product QEMU. No Rust
 * library is linked into QEMU. Limits are installed by its retained host owner;
 * this gate cannot grant authority or accept a PID to administer.
 */
#include "sandsurf-entry.h"
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sandbox.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static void gate_failed(void)
{
    _exit(70);
}

static int64_t milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) {
        gate_failed();
    }
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void transfer(void *buffer, size_t bytes, int writing, int64_t deadline)
{
    unsigned char *cursor = buffer;
    while (bytes) {
        int64_t remaining = deadline - milliseconds();
        struct pollfd fd = { .fd = 3, .events = writing ? POLLOUT : POLLIN };
        if (remaining <= 0) {
            gate_failed();
        }
        int ready = poll(&fd, 1, (int)remaining);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready <= 0 || (fd.revents & (POLLERR | POLLNVAL))) {
            gate_failed();
        }
        ssize_t count = writing ? write(3, cursor, bytes) : read(3, cursor, bytes);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }
        if (count <= 0) {
            gate_failed();
        }
        cursor += count;
        bytes -= (size_t)count;
    }
}

static uint64_t little_u64(const unsigned char *bytes)
{
    uint64_t value = 0;
    for (int index = 7; index >= 0; --index) {
        value = (value << 8) | bytes[index];
    }
    return value;
}

static void *owner_watch(void *unused)
{
    unsigned char byte;
    (void)unused;
    while (read(3, &byte, 1) < 0 && errno == EINTR) {
    }
    gate_failed();
    return NULL;
}

static void darwin_gate(unsigned custody_count, const char *profile)
{
    uid_t uid;
    gid_t gid;
    int type = 0, peer = 0, one = 1;
    socklen_t size = sizeof(type);
    unsigned char budget[32];
    pthread_t watcher;
    if (geteuid() == 0 || getppid() <= 1 ||
        getsockopt(3, SOL_SOCKET, SO_TYPE, &type, &size) ||
        size != sizeof(type) || type != SOCK_STREAM ||
        getpeereid(3, &uid, &gid) || uid != 0 ||
        setsockopt(3, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) ||
        fcntl(3, F_SETFD, FD_CLOEXEC) || fcntl(3, F_SETFL, O_NONBLOCK)) {
        gate_failed();
    }
    for (unsigned index = 0; index < custody_count; ++index) {
        if (fcntl(5 + (int)index, F_SETFD, FD_CLOEXEC)) {
            gate_failed();
        }
    }
    int64_t deadline = milliseconds() + 15000;
    char ready[] = "SSRDY001";
    transfer(ready, 8, 1, deadline);
    transfer(budget, sizeof(budget), 0, deadline);
    size = sizeof(peer);
    if (getsockopt(3, SOL_LOCAL, LOCAL_PEERPID, &peer, &size) ||
        size != sizeof(peer) || peer != getppid() ||
        memcmp(budget, "SSBUD001", 8) ||
        little_u64(budget + 8) < 1000 ||
        little_u64(budget + 8) > 255000 ||
        little_u64(budget + 8) % 1000 ||
        little_u64(budget + 16) < 64 * 1024 * 1024 ||
        little_u64(budget + 16) > (uint64_t)INT32_MAX * 1024 * 1024 ||
        little_u64(budget + 16) % (1024 * 1024) ||
        budget[24] != 1 || memcmp(budget + 25, "\0\0\0\0\0\0\0", 7)) {
        gate_failed();
    }
    /* A VMM never launches native child programs. Guest fork/exec remains
     * unrestricted: this policy constrains only the host QEMU process. */
    char *error = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    int status = sandbox_init(profile, 0, &error);
    if (error) {
        sandbox_free_error(error);
    }
#pragma clang diagnostic pop
    if (status) {
        gate_failed();
    }
    char acknowledged[] = "SSACK001";
    transfer(acknowledged, 8, 1, deadline);
    if (fcntl(3, F_SETFL, 0) || pthread_create(&watcher, NULL, owner_watch, NULL) ||
        pthread_detach(watcher)) {
        gate_failed();
    }
}
#endif

static uint32_t guest_cpu_cap;

uint32_t sandsurf_qemu_cpu_cap(void)
{
    /* Only a WHPX worker receives a separate hypervisor scheduling allowance.
     * The native Windows Job limit does not establish guest CPU enforcement. */
    return guest_cpu_cap;
}

int sandsurf_qemu_enter(int argc, char ***argv)
{
#ifdef __APPLE__
    if (argc < 8 || strcmp((*argv)[1], "--broker-worker") ||
        strcmp((*argv)[2], "virtual-machine") ||
        strcmp((*argv)[3], "--owned-leases") ||
        strlen((*argv)[4]) != 1 || (*argv)[4][0] < '1' || (*argv)[4][0] > '8' ||
        strcmp((*argv)[5], "--sandsurf-seatbelt") ||
        !(*argv)[6][0] || strlen((*argv)[6]) > 65536) {
        _exit(70);
    }
    darwin_gate((unsigned)((*argv)[4][0] - '0'), (*argv)[6]);
    memmove(*argv + 1, *argv + 7, (size_t)(argc - 6) * sizeof(char *));
    return argc - 6;
#elif defined(_WIN32)
    if (argc < 4 || strcmp((*argv)[1], "--sandsurf-cpu-cap")) {
        exit(70);
    }
    const char *number = (*argv)[2];
    if (!*number || strlen(number) > 5) {
        exit(70);
    }
    for (const char *digit = number; *digit; ++digit) {
        if (*digit < '0' || *digit > '9') {
            exit(70);
        }
        guest_cpu_cap = guest_cpu_cap * 10 + (uint32_t)(*digit - '0');
    }
    if (guest_cpu_cap == 0 || guest_cpu_cap > 65536) {
        exit(70);
    }
    memmove(*argv + 1, *argv + 3, (size_t)(argc - 2) * sizeof(char *));
    return argc - 2;
#else
    /* Linux machine ownership remains Firecracker; never make this entry a
     * software-emulation fallback for another host. */
    (void)argc;
    (void)argv;
    exit(70);
#endif
}
