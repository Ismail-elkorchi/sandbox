/* Actual PF socket-origin and local-delivery contract, not VM qualification.
 * Run only in the disposable Darwin CI runner with the accompanying rules.
 * The factory exits before the transferred sockets are used. No PID lookup,
 * destination enumeration, or guest cooperation participates in the denial.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define FACTORY_UID 65530
#define DEADLINE_MS 300

static void require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "Darwin local-delivery contract: %s (errno=%d)\n", message, errno);
        exit(1);
    }
}

static int restricted_socket(int family, int type)
{
    int channel[2];
    require(socketpair(AF_UNIX, SOCK_DGRAM, 0, channel) == 0, "factory channel");
    pid_t child = fork();
    require(child >= 0, "factory fork");
    if (child == 0) {
        close(channel[0]);
        require(setgid(FACTORY_UID) == 0 && setuid(FACTORY_UID) == 0, "factory credential");
        int descriptor = socket(family, type, 0);
        require(descriptor >= 0, "factory native socket");
        uint8_t payload = 1;
        struct iovec iov = {.iov_base = &payload, .iov_len = 1};
        union { struct cmsghdr align; uint8_t bytes[CMSG_SPACE(sizeof(int))]; } ancillary = {0};
        struct msghdr message = {0};
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.bytes;
        message.msg_controllen = sizeof(ancillary.bytes);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
        require(sendmsg(channel[1], &message, 0) == 1, "original socket transfer");
        close(descriptor);
        close(channel[1]);
        _exit(0);
    }
    close(channel[1]);
    struct pollfd ready = {.fd = channel[0], .events = POLLIN};
    require(poll(&ready, 1, 3000) == 1, "factory receipt deadline");
    uint8_t payload = 0;
    struct iovec iov = {.iov_base = &payload, .iov_len = 1};
    union { struct cmsghdr align; uint8_t bytes[CMSG_SPACE(sizeof(int))]; } ancillary = {0};
    struct msghdr message = {0};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.bytes;
    message.msg_controllen = sizeof(ancillary.bytes);
    require(recvmsg(channel[0], &message, 0) == 1 && payload == 1 &&
            (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0, "complete factory receipt");
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    require(header != NULL && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
            header->cmsg_len == CMSG_LEN(sizeof(int)) && CMSG_NXTHDR(&message, header) == NULL,
            "exact original socket custody");
    int descriptor = -1;
    memcpy(&descriptor, CMSG_DATA(header), sizeof(descriptor));
    require(descriptor >= 0 && fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0, "private socket receipt");
    close(channel[0]);
    int status = 0;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "factory native exit before socket use");
    return descriptor;
}

static socklen_t address(struct sockaddr_storage *storage, int family, const char *text, uint16_t port)
{
    memset(storage, 0, sizeof(*storage));
    if (family == AF_INET) {
        struct sockaddr_in *value = (struct sockaddr_in *)storage;
        value->sin_family = AF_INET;
        value->sin_len = sizeof(*value);
        value->sin_port = htons(port);
        require(inet_pton(family, text, &value->sin_addr) == 1, "IPv4 fixture address");
        return sizeof(*value);
    }
    struct sockaddr_in6 *value = (struct sockaddr_in6 *)storage;
    value->sin6_family = AF_INET6;
    value->sin6_len = sizeof(*value);
    value->sin6_port = htons(port);
    require(inet_pton(family, text, &value->sin6_addr) == 1, "IPv6 fixture address");
    return sizeof(*value);
}

static int listener(int family, int type, const char *text, struct sockaddr_storage *target, socklen_t *length)
{
    int descriptor = socket(family, type, 0);
    require(descriptor >= 0, "local fixture socket");
    *length = address(target, family, text, 0);
    require(bind(descriptor, (struct sockaddr *)target, *length) == 0, "local fixture bind");
    require(getsockname(descriptor, (struct sockaddr *)target, length) == 0, "assigned fixture port");
    if (type == SOCK_STREAM) require(listen(descriptor, 1) == 0, "local fixture listen");
    return descriptor;
}

static void readable(int descriptor, int expected, const char *message)
{
    struct pollfd ready = {.fd = descriptor, .events = POLLIN};
    int result;
    do { result = poll(&ready, 1, DEADLINE_MS); } while (result < 0 && errno == EINTR);
    require(expected ? result == 1 && (ready.revents & POLLIN) != 0 : result == 0, message);
}

static void local_contract(int family, const char *text)
{
    const int types[] = {SOCK_STREAM, SOCK_DGRAM};
    for (size_t index = 0; index < sizeof(types) / sizeof(types[0]); index++) {
        int type = types[index];
        fprintf(stderr, "local-delivery case: %s %s\n", text, type == SOCK_STREAM ? "TCP" : "UDP");
        struct sockaddr_storage target;
        socklen_t length;
        int server = listener(family, type, text, &target, &length);
        int ordinary = socket(family, type, 0);
        require(ordinary >= 0 && connect(ordinary, (struct sockaddr *)&target, length) == 0,
                "ordinary local control connect");
        if (type == SOCK_STREAM) {
            readable(server, 1, "ordinary TCP local delivery");
            int accepted = accept(server, NULL, NULL);
            require(accepted >= 0, "ordinary TCP accept");
            close(accepted);
        } else {
            require(send(ordinary, "control", 7, 0) == 7, "ordinary UDP control send");
            readable(server, 1, "ordinary UDP local delivery");
            char bytes[16];
            require(recv(server, bytes, sizeof(bytes), 0) == 7, "ordinary UDP control receive");
        }
        close(ordinary);
        int restricted = restricted_socket(family, type);
        require(fcntl(restricted, F_SETFL, O_NONBLOCK) == 0, "bounded native connect");
        int connected = connect(restricted, (struct sockaddr *)&target, length);
        if (type == SOCK_DGRAM) {
            require(connected == 0, "restricted UDP connect is not delivery authority");
            /* PF may reject submission or drop it later; only actual absence
             * at the host listener is the property being tested. */
            (void)send(restricted, "forbidden", 9, 0);
        }
        readable(server, 0, "factory socket reached host-local TCP/UDP after factory exit");
        close(restricted);
        close(server);
    }
}

static void route_change_contract(void)
{
    struct sockaddr_storage remote;
    socklen_t length = address(&remote, AF_INET, "198.18.0.9", 28913);
    int restricted = restricted_socket(AF_INET, SOCK_DGRAM);
    require(connect(restricted, (struct sockaddr *)&remote, length) == 0, "original remote tuple");
    (void)send(restricted, "remote", 6, 0);
    pid_t child = fork();
    require(child >= 0, "route transition helper");
    if (child == 0) {
        execl("/sbin/ifconfig", "ifconfig", "lo0", "alias", "198.18.0.9", "netmask", "255.255.255.255", NULL);
        _exit(1);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "destination becomes locally delivered");
    int server = socket(AF_INET, SOCK_DGRAM, 0);
    require(server >= 0 && bind(server, (struct sockaddr *)&remote, length) == 0, "new local destination");
    (void)send(restricted, "forbidden", 9, 0);
    readable(server, 0, "existing transferred UDP tuple reached newly local destination");
    close(server);
    close(restricted);
}

int main(void)
{
    require(getuid() == 0, "disposable runner root is required explicitly");
    local_contract(AF_INET, "127.0.0.1");
    local_contract(AF_INET6, "::1");
    route_change_contract();
    puts("original-socket-owner-exit, IPv4/IPv6 TCP/UDP local delivery, and live UDP route transition: passed");
    return 0;
}
