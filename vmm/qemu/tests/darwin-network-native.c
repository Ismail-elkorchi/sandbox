/* Compile/link the actual SDK shim and test its running-vnode observation and
 * original audit-token lifetime without requiring VM hardware. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int sandsurf_darwin_running_executable(void);
int sandsurf_darwin_peer_identity(int, uint32_t[8]);
int sandsurf_darwin_peer_alive(const uint32_t[8]);
static void require(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "%s (errno=%d)\n", message, errno); exit(1); }
}
int main(void) {
    int executable = sandsurf_darwin_running_executable();
    require(executable >= 0, "running mapped-vnode identity");
    struct stat original;
    require(fstat(executable, &original) == 0 && original.st_size > 0, "original executable file");
    close(executable);
    int channel[2];
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, channel) == 0, "original observation channel");
    uint32_t token[8];
    require(sandsurf_darwin_peer_identity(channel[0], token) == 0 &&
            sandsurf_darwin_peer_alive(token) == 0, "original live peer identity");
    close(channel[0]); close(channel[1]);
    puts("SDK-compiled mapped executable and original peer audit-token observation: passed");
    return 0;
}
