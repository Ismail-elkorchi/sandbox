/* Ordinary-kernel experiment, not a runtime or a WHPX qualification. It asks
 * whether native network isolation follows an original socket after transfer,
 * owner exit, and a remote destination becoming local. Never install a product
 * path based on an initial connect check or an address-cache observation. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <windows.h>
#include <sddl.h>
#include <userenv.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "%s (Win32=%lu, Winsock=%d)\n", message,
                (unsigned long)GetLastError(), WSAGetLastError());
        exit(1);
    }
}
static struct sockaddr_in address(const char *ip, unsigned short port) {
    struct sockaddr_in value = {0};
    value.sin_family = AF_INET;
    value.sin_port = htons(port);
    value.sin_addr.s_addr = inet_addr(ip);
    return value;
}
static SOCKET udp_listener(const char *ip, unsigned short *port) {
    SOCKET socket = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0,
                              WSA_FLAG_OVERLAPPED);
    require(socket != INVALID_SOCKET, "ordinary UDP allocation");
    struct sockaddr_in local = address(ip, *port);
    require(bind(socket, (struct sockaddr *)&local, sizeof(local)) == 0,
            "ordinary UDP bind");
    int bytes = sizeof(local);
    require(getsockname(socket, (struct sockaddr *)&local, &bytes) == 0,
            "ordinary UDP name");
    *port = ntohs(local.sin_port);
    DWORD timeout = 300;
    require(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                      (const char *)&timeout, sizeof(timeout)) == 0,
            "ordinary UDP deadline");
    return socket;
}
static int delivered(SOCKET sender, SOCKET receiver, const char *ip,
                     unsigned short port) {
    struct sockaddr_in destination = address(ip, port);
    int sent = sendto(sender, "boundary", 8, 0,
                      (struct sockaddr *)&destination, sizeof(destination));
    char bytes[16] = {0};
    int received = recv(receiver, bytes, sizeof(bytes), 0);
    printf("UDP %s: send=%d receive=%d error=%d\n", ip, sent, received,
           WSAGetLastError());
    fflush(stdout);
    return received == 8 && memcmp(bytes, "boundary", 8) == 0;
}
static void child(DWORD recipient) {
    WSAPROTOCOL_INFOW receipts[2] = {0};
    for (int slot = 0; slot < 2; ++slot) {
        int type = slot == 0 ? SOCK_STREAM : SOCK_DGRAM;
        int protocol = slot == 0 ? IPPROTO_TCP : IPPROTO_UDP;
        SOCKET socket = WSASocketW(AF_INET, type, protocol, NULL, 0,
                                  WSA_FLAG_OVERLAPPED);
        require(socket != INVALID_SOCKET, "restricted socket allocation");
        struct sockaddr_in local = address("0.0.0.0", 0);
        require(bind(socket, (struct sockaddr *)&local, sizeof(local)) == 0,
                "original restricted socket bind");
        require(WSADuplicateSocketW(socket, recipient, &receipts[slot]) == 0,
                "original restricted socket transfer");
        /* The last child descriptor closes at process exit. The parent's
         * duplicate is the only live owner when it starts using the socket. */
    }
    DWORD written = 0;
    require(WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), receipts,
                      sizeof(receipts), &written, NULL) &&
                written == sizeof(receipts), "original socket receipts");
}
static void alias(int add) {
    /* This executable runs only on a disposable elevated CI host. The caller
     * removes exactly the fixture address even when the experiment fails. */
    const char *command = add
        ? "powershell.exe -NoProfile -NonInteractive -Command \"New-NetIPAddress -InterfaceIndex 1 -IPAddress 198.18.0.9 -PrefixLength 32 -AddressFamily IPv4 -ErrorAction Stop | Out-Null\""
        : "powershell.exe -NoProfile -NonInteractive -Command \"Remove-NetIPAddress -InterfaceIndex 1 -IPAddress 198.18.0.9 -Confirm:$false -ErrorAction Stop\"";
    require(system(command) == 0, add ? "fixture address acquisition" :
                                     "fixture address removal");
}
static int experiment(const wchar_t *binary) {
    wchar_t name[80];
    swprintf(name, sizeof(name) / sizeof(*name), L"ss-net-proof-%lu-%llu",
             (unsigned long)GetCurrentProcessId(),
             (unsigned long long)GetTickCount64());
    PSID sid = NULL;
    require(SUCCEEDED(DeriveAppContainerSidFromAppContainerName(name, &sid)),
            "fresh AppContainer identity");
    LPWSTR sid_text = NULL;
    require(ConvertSidToStringSidW(sid, &sid_text), "AppContainer SID text");
    wchar_t temporary[MAX_PATH], executable[MAX_PATH];
    require(GetTempPathW(MAX_PATH, temporary) > 0, "fixture temp path");
    require(swprintf(executable, MAX_PATH, L"%ls%ls.exe", temporary, name) > 0,
            "fixture binary path");
    require(CopyFileW(binary, executable, TRUE), "fixture binary copy");
    wchar_t acl[256];
    require(swprintf(acl, 256,
        L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;%ls)", sid_text) > 0,
        "fixture binary ACL");
    PSECURITY_DESCRIPTOR descriptor = NULL;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                acl, SDDL_REVISION_1, &descriptor, NULL), "fixture descriptor");
    require(SetFileSecurityW(executable, DACL_SECURITY_INFORMATION |
                PROTECTED_DACL_SECURITY_INFORMATION, descriptor), "fixture ACL");
    LocalFree(descriptor);
    LocalFree(sid_text);
    unsigned char internet[SECURITY_MAX_SID_SIZE], private_net[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof(internet);
    require(CreateWellKnownSid(WinCapabilityInternetClientSid, NULL, internet,
                              &sid_size), "Internet capability");
    sid_size = sizeof(private_net);
    require(CreateWellKnownSid(WinCapabilityPrivateNetworkClientServerSid, NULL,
                              private_net, &sid_size), "private capability");
    SID_AND_ATTRIBUTES capabilities[2] = {
        {internet, SE_GROUP_ENABLED}, {private_net, SE_GROUP_ENABLED}};
    SECURITY_CAPABILITIES security = {sid, capabilities, 2, 0};
    SIZE_T attribute_bytes = 0;
    InitializeProcThreadAttributeList(NULL, 3, 0, &attribute_bytes);
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = malloc(attribute_bytes);
    require(attributes != NULL && InitializeProcThreadAttributeList(
                attributes, 3, 0, &attribute_bytes), "native launch attributes");
    SECURITY_ATTRIBUTES inheritance = {sizeof(inheritance), NULL, TRUE};
    HANDLE read_pipe, write_pipe;
    require(CreatePipe(&read_pipe, &write_pipe, &inheritance, 0), "receipt pipe");
    require(SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0),
            "private receipt reader");
    require(UpdateProcThreadAttribute(attributes, 0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &write_pipe,
                sizeof(write_pipe), NULL, NULL), "explicit receipt inheritance");
    require(UpdateProcThreadAttribute(attributes, 0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security,
                sizeof(security), NULL, NULL), "original network identity");
    DWORD policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    require(UpdateProcThreadAttribute(attributes, 0,
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &policy,
                sizeof(policy), NULL, NULL), "low-privilege policy");
    STARTUPINFOEXW startup = {0};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdOutput = write_pipe;
    startup.lpAttributeList = attributes;
    wchar_t command[2 * MAX_PATH];
    require(swprintf(command, 2 * MAX_PATH, L"\"%ls\" child %lu", executable,
              (unsigned long)GetCurrentProcessId()) > 0, "fixture child command");
    PROCESS_INFORMATION process = {0};
    require(CreateProcessW(executable, command, NULL, NULL, TRUE,
                EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                &startup.StartupInfo, &process), "restricted native socket owner");
    CloseHandle(write_pipe);
    WSAPROTOCOL_INFOW receipts[2] = {0};
    DWORD offset = 0;
    while (offset < sizeof(receipts)) {
        DWORD count = 0;
        require(ReadFile(read_pipe, (char *)receipts + offset,
                         sizeof(receipts) - offset, &count, NULL) && count > 0,
                "transferred original socket receipt");
        offset += count;
    }
    SOCKET sockets[2];
    for (int slot = 0; slot < 2; ++slot) {
        sockets[slot] = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
            FROM_PROTOCOL_INFO, &receipts[slot], 0, WSA_FLAG_OVERLAPPED);
        require(sockets[slot] != INVALID_SOCKET, "adopt original socket");
    }
    require(WaitForSingleObject(process.hProcess, 5000) == WAIT_OBJECT_0,
            "original owner exited");
    DWORD exit_code = 0;
    require(GetExitCodeProcess(process.hProcess, &exit_code) && exit_code == 0,
            "native socket owner succeeded");
    CloseHandle(process.hProcess);
    CloseHandle(process.hThread);
    CloseHandle(read_pipe);
    DeleteProcThreadAttributeList(attributes);
    free(attributes);
    FreeSid(sid);
    require(DeleteFileW(executable), "fixture binary cleanup");

    unsigned short port = 0;
    SOCKET receiver = udp_listener("127.0.0.1", &port);
    unsigned short unused = 0;
    SOCKET control = udp_listener("0.0.0.0", &unused);
    require(delivered(control, receiver, "127.0.0.1", port),
            "ordinary local control must work");
    int failures = delivered(sockets[1], receiver, "127.0.0.1", port);
    closesocket(receiver);
    SOCKET listener = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                                WSA_FLAG_OVERLAPPED);
    require(listener != INVALID_SOCKET, "TCP receiver allocation");
    struct sockaddr_in local = address("127.0.0.1", 0);
    require(bind(listener, (struct sockaddr *)&local, sizeof(local)) == 0 &&
                listen(listener, 1) == 0, "TCP receiver admission");
    int size = sizeof(local);
    require(getsockname(listener, (struct sockaddr *)&local, &size) == 0,
            "TCP receiver address");
    int connected = connect(sockets[0], (struct sockaddr *)&local, sizeof(local));
    printf("Transferred TCP local connect=%d error=%d\n", connected, WSAGetLastError());
    if (connected == 0) ++failures;
    closesocket(listener);

    /* Establish UDP before any local address exists; use the same original
     * endpoint after the destination changes its local-delivery classification. */
    struct sockaddr_in remote = address("198.18.0.9", port);
    require(connect(sockets[1], (struct sockaddr *)&remote, sizeof(remote)) == 0,
            "original remote UDP flow");
    (void)send(sockets[1], "before", 6, 0);
    alias(1);
    receiver = udp_listener("198.18.0.9", &port);
    require(delivered(control, receiver, "198.18.0.9", port),
            "ordinary newly-local control must work");
    int sent = send(sockets[1], "boundary", 8, 0);
    char bytes[16] = {0};
    int received = recv(receiver, bytes, sizeof(bytes), 0);
    printf("Transferred UDP newly-local: send=%d receive=%d error=%d\n",
           sent, received, WSAGetLastError());
    if (received == 8 && memcmp(bytes, "boundary", 8) == 0) ++failures;
    closesocket(receiver);
    alias(0);
    closesocket(control);
    closesocket(sockets[0]);
    closesocket(sockets[1]);
    printf("Native isolation violations: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
int main(int argc, char **argv) {
    WSADATA data;
    require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Winsock initialization");
    if (argc == 3 && strcmp(argv[1], "child") == 0) {
        child((DWORD)strtoul(argv[2], NULL, 10));
        return 0;
    }
    wchar_t binary[MAX_PATH];
    require(GetModuleFileNameW(NULL, binary, MAX_PATH) > 0, "fixture executable");
    int result = experiment(binary);
    WSACleanup();
    return result;
}
