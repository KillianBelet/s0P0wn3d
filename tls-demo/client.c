/*
 * client.c - Client TLS.
 * Toute la partie TLS est dans tls.c ; ici il n'y a que la logique de l'application.
 * Usage : client.exe [ip_serveur]   (sinon SERVER_IP du fichier .env)
 */
#include <stdio.h>   /* printf, fprintf, fgets */
#include <string.h>  /* strlen */
#include "tls.h"     /* notre module TLS */

#define BUFFER_SIZE 1024 /* taille max d'un message */

int main(int argc, char *argv[])
{
    const char *ip;
    tls_conn *c = NULL;       /* NULL : tls_close(NULL) reste sûr en cas d'échec précoce */
    char buffer[BUFFER_SIZE]; /* sert à la fois pour le message envoyé et la réponse */
    size_t len;               /* size_t = type non signé pour les tailles */
    int n, status = 1;        /* 1 = échec par défaut, passe à 0 seulement si tout réussit */

    cfg_load(".env");  /* absent = valeurs par défaut */
    /* IP du serveur : argument en ligne de commande, sinon .env, sinon loopback. */
    ip = (argc >= 2) ? argv[1] : cfg_get("SERVER_IP", "127.0.0.1");

    if (tls_init() != 0) { fprintf(stderr, "Init reseau impossible\n"); return 1; }

    /* Connexion TCP + handshake TLS + vérification du certificat serveur. */
    c = tls_connect(ip, cfg_port());
    if (!c) goto cleanup;
    printf("Connecté en %s au serveur %s:%d\n", tls_version(c), ip, cfg_port());

    printf("Enter message: ");
    fflush(stdout); /* le prompt n'a pas de '\n' : on force son affichage */
    /* fgets lit au plus BUFFER_SIZE-1 caractères : impossible de déborder.
     * NULL = fin d'entrée (Ctrl+Z) ou erreur. */
    if (fgets(buffer, BUFFER_SIZE, stdin) == NULL) { fprintf(stderr, "Aucun message lu\n"); goto cleanup; }
    len = strlen(buffer);
    /* fgets garde le '\n' de la touche Entrée : on le retire.
     * "--len" décrémente d'abord, donc on écrit '\0' à la place du '\n'. */
    if (len > 0 && buffer[len - 1] == '\n') buffer[--len] = '\0';
    if (len == 0) { fprintf(stderr, "Message vide refusé\n"); goto cleanup; }

    /* Envoi chiffré (on n'envoie pas le '\0', seulement len octets). */
    if (tls_send(c, buffer, (int)len) <= 0) goto cleanup;
    /* Réception de la réponse ; on garde une case pour le '\0'. */
    n = tls_recv(c, buffer, BUFFER_SIZE - 1);
    if (n <= 0) goto cleanup;
    buffer[n] = '\0'; /* transforme les octets reçus en chaîne C */
    printf("Received: %s\n", buffer);
    status = 0;

/* Sortie unique : libération systématique des ressources. */
cleanup:
    tls_close(c);
    tls_cleanup();
    return status;
}
