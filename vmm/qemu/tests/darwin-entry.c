/* Exercise the actual product entry gate on a disposable CI host. No VM,
 * emulation, guest management or replacement implementation of the gate. */
#include "sandsurf-entry.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void cannot_open(const char *path, int flags)
{
    int fd = open(path, flags, 0600);
    if (fd >= 0) {
        close(fd);
        fprintf(stderr, "escaped native file policy: %s\n", path);
        _exit(99);
    }
    assert(errno == EPERM || errno == EACCES);
}

static struct sockaddr_un address(const char *path)
{
    struct sockaddr_un result = { .sun_family = AF_UNIX };
    assert(strlen(path) < sizeof(result.sun_path));
    strcpy(result.sun_path, path);
    return result;
}

static void cannot_use_ip(int family, int type)
{
    // macOS does not consistently mediate socket allocation. Test actual
    // authority: no bind, connection, or datagram may reach the host network.
    int fd = socket(family, type, 0);
    if (fd < 0) {
        assert(errno == EPERM || errno == EACCES);
        return;
    }
    assert(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    struct sockaddr_in v4 = { .sin_len = sizeof(v4), .sin_family = AF_INET,
        .sin_port = htons(9), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    struct sockaddr_in6 v6 = { .sin6_len = sizeof(v6), .sin6_family = AF_INET6,
        .sin6_port = htons(9), .sin6_addr = IN6ADDR_LOOPBACK_INIT };
    const struct sockaddr *peer = family == AF_INET
        ? (const struct sockaddr *)&v4 : (const struct sockaddr *)&v6;
    socklen_t size = family == AF_INET ? sizeof(v4) : sizeof(v6);
    assert(connect(fd, peer, size) == -1 && (errno == EPERM || errno == EACCES));
    if (type == SOCK_DGRAM) {
        assert(sendto(fd, "X", 1, 0, peer, size) == -1
            && (errno == EPERM || errno == EACCES));
    }
    v4.sin_port = 0;
    v6.sin6_port = 0;
    assert(bind(fd, peer, size) == -1 && (errno == EPERM || errno == EACCES));
    close(fd);
}

int main(int argc, char **argv)
{
    argc = sandsurf_qemu_enter(argc, &argv);
    assert(argc == 8 && argv[argc] == NULL);
    int disk = open(argv[1], O_RDWR);
    assert(disk >= 0 && pwrite(disk, "D", 1, 0) == 1 && fsync(disk) == 0);
    close(disk);
    assert(unlink(argv[1]) == -1 && (errno == EPERM || errno == EACCES));
    int input = open(argv[2], O_RDONLY);
    char byte;
    assert(input >= 0 && read(input, &byte, 1) == 1 && byte == 'R');
    // Read-only descriptors must not be an extent-transfer mutation escape.
    assert(fcntl(input, 80, 0) == -1 && (errno == EPERM || errno == EACCES));
    assert(fcntl(input, 110, 0) == -1 && (errno == EPERM || errno == EACCES));
    close(input);
    cannot_open(argv[2], O_WRONLY);
    cannot_open(argv[3], O_RDONLY);
    cannot_open(argv[3], O_WRONLY);
    int capture = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (capture < 0) {
        perror("admitted native capture open");
        _exit(99);
    }
    assert(write(capture, "S", 1) == 1);
    assert(fsync(capture) == 0);
    close(capture);
    cannot_open(argv[5], O_WRONLY | O_CREAT);
    // The native machine has only AF_UNIX device endpoints, never host IP
    // network delivery or access to some unrelated host Unix service.
    cannot_use_ip(AF_INET, SOCK_STREAM);
    cannot_use_ip(AF_INET, SOCK_DGRAM);
    cannot_use_ip(AF_INET6, SOCK_STREAM);
    cannot_use_ip(AF_INET6, SOCK_DGRAM);
    int outgoing = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un other = address(argv[7]);
    assert(outgoing >= 0);
    assert(connect(outgoing, (struct sockaddr *)&other, sizeof(other)) == -1);
    assert(errno == EPERM || errno == EACCES);
    close(outgoing);
    assert(fork() == -1 && (errno == EPERM || errno == EACCES));
    char *attempt[] = { argv[2], NULL };
    assert(execv(argv[2], attempt) == -1 && (errno == EPERM || errno == EACCES));
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un endpoint = address(argv[6]);
    assert(listener >= 0);
    assert(bind(listener, (struct sockaddr *)&endpoint, sizeof(endpoint)) == 0);
    assert(listen(listener, 1) == 0);
    int client = accept(listener, NULL, NULL);
    assert(client >= 0 && read(client, &byte, 1) == 1 && byte == 'P');
    assert(write(client, "A", 1) == 1);
    close(client);
    close(listener);
    return 0;
}
