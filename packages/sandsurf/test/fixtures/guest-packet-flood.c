/* Qualification stimulus only. The host compiles these reviewed bytes, then
 * transfers the static program into the real guest. Only the guest invocation
 * opens an AF_PACKET socket; --self-test has no network or privilege effects.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define CASES 6
#define COUNT 32768
#define SIZE 1514

static void frame(uint8_t bytes[SIZE], unsigned int variant, const uint8_t mac[6])
{
    memset(bytes, 0, SIZE);
    const uint8_t gateway[6] = {2, 0, 0, 0, 0, 1};
    memcpy(bytes, gateway, 6);
    memcpy(bytes + 6, mac, 6);
    bytes[12] = 8; /* IPv4 */
    bytes[14] = 0x45;
    bytes[16] = 5; bytes[17] = 220; /* 1500-byte datagram */
    bytes[22] = 64; bytes[23] = 17;
    bytes[26] = 100; bytes[27] = 64; bytes[29] = 2;
    bytes[30] = 1; bytes[31] = 1; bytes[32] = 1; bytes[33] = 1;
    switch (variant) {
    case 0: bytes[14] = 0x44; break; /* impossible IPv4 header length */
    case 1: bytes[20] = 0x20; break; /* forbidden IPv4 fragmentation */
    case 2: bytes[12] = 0x81; bytes[13] = 0; break; /* VLAN */
    case 3: bytes[6] ^= 4; break; /* forged machine source identity */
    case 4:
        bytes[12] = 0x86; bytes[13] = 0xdd; bytes[14] = 0x60;
        bytes[20] = 44; /* unsupported IPv6 fragment header */
        break;
    case 5: bytes[16] = 0xff; bytes[17] = 0xff; break; /* truncated IP length */
    default: abort();
    }
}

int main(int argc, char **argv)
{
    uint8_t bytes[SIZE];
    const uint8_t fixture_mac[6] = {2, 1, 2, 3, 4, 5};
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        for (unsigned int i = 0; i < CASES; i++) frame(bytes, i, fixture_mac);
        printf("cases=%d packets=%d maximumFrameBytes=%d\n", CASES, COUNT, SIZE);
        return 0;
    }
    if (argc != 1 || geteuid() != 0) return 64;
    int descriptor = socket(AF_PACKET, SOCK_RAW, htons(3)); /* ETH_P_ALL */
    if (descriptor < 0) { perror("guest raw NIC socket"); return 1; }
    struct ifreq request = {0};
    memcpy(request.ifr_name, "eth0", 5);
    if (ioctl(descriptor, SIOCGIFINDEX, &request) != 0) return 1;
    struct sockaddr_ll destination = {0};
    destination.sll_family = AF_PACKET;
    destination.sll_ifindex = request.ifr_ifindex;
    destination.sll_halen = 6;
    memcpy(destination.sll_addr, "\x02\0\0\0\0\x01", 6);
    if (ioctl(descriptor, SIOCGIFHWADDR, &request) != 0) return 1;
    struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
    if (setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) return 1;
    unsigned int sent = 0;
    for (unsigned int i = 0; i < COUNT; i++) {
        frame(bytes, i % CASES, (const uint8_t *)request.ifr_hwaddr.sa_data);
        ssize_t result;
        do {
            result = sendto(descriptor, bytes, SIZE, 0,
                            (const struct sockaddr *)&destination, sizeof(destination));
        } while (result < 0 && errno == EINTR);
        if (result != SIZE) { perror("guest raw NIC submission"); close(descriptor); return 1; }
        sent++;
        /* Sustain traffic across independent native-control observations,
         * rather than finishing before the host starts its control probes. */
        if (i % 128 == 127) usleep(10000);
    }
    close(descriptor);
    printf("cases=%d packets=%u maximumFrameBytes=%d\n", CASES, sent, SIZE);
    return 0;
}
