/*
 * server.c - Serveur TLS mono-client : lit un message, renvoie "ECHO: <message>".
 * Toute la partie TLS est dans tls.c.
 * Usage : server.exe [ip_ecoute]   (sinon SERVER_BIND_IP du fichier .env, défaut 127.0.0.1)
 */
#include <stdio.h>  /* printf, fprintf, snprintf */
#include "tls.h"    /* notre module : on ne voit ni OpenSSL ni Winsock ici */

#define BUFFER_SIZE 1024 /* taille max d'un message reçu */

/* argc = nombre d'arguments ; argv = les arguments (argv[0] = nom du programme). */
int main(int argc, char *argv[])
{
    const char *ip;
    tls_conn *c = NULL;          /* NULL au départ : tls_close(NULL) est sans risque */
    char buffer[BUFFER_SIZE];    /* message reçu du client */
    char reply[BUFFER_SIZE + 8]; /* réponse : "ECHO: " (6 car.) + message + '\0' */
    int n, status = 1;           /* status = code de retour ; 1 = échec tant qu'on n'a pas réussi */

    /* Lit la configuration ; si .env est absent, les valeurs par défaut servent. */
    cfg_load(".env");
    /* Priorité : argument de la ligne de commande, sinon .env, sinon 127.0.0.1
     * (loopback = uniquement accessible depuis la machine elle-même). */
    ip = (argc >= 2) ? argv[1] : cfg_get("SERVER_BIND_IP", "127.0.0.1");

    if (tls_init() != 0) { fprintf(stderr, "Init reseau impossible\n"); return 1; }

    /* Attend un client et fait le handshake TLS (bloquant). */
    c = tls_accept_one(ip, cfg_port());
    if (!c) goto cleanup;
    printf("Client authentifié (%s)\n", tls_version(c));

    /* BUFFER_SIZE - 1 : on garde 1 case pour le '\0' final. */
    n = tls_recv(c, buffer, BUFFER_SIZE - 1);
    if (n <= 0) goto cleanup;
    /* Les données reçues ne sont PAS une chaîne C : on ajoute nous-mêmes
     * le '\0' pour pouvoir utiliser printf("%s"). */
    buffer[n] = '\0';
    printf("Reçu : %s\n", buffer);

    /* snprintf écrit au plus sizeof(reply) octets : pas de débordement.
     * Il renvoie la longueur écrite (négatif = erreur). */
    n = snprintf(reply, sizeof(reply), "ECHO: %s", buffer);
    if (n < 0 || tls_send(c, reply, n) <= 0) goto cleanup;
    status = 0; /* tout s'est bien passé */

/* Sortie unique : on libère toujours, que ce soit un succès ou un échec. */
cleanup:
    tls_close(c);
    tls_cleanup();
    return status;
}
