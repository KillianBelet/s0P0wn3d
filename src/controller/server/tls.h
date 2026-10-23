/*
 * tls.h - Module TLS réutilisable (Linux / GCC / OpenSSL).
 *
 * Ce header ne contient que des DÉCLARATIONS ; l'implémentation est dans tls.c.
 * c2_server.c et implant.c font #include "tls.h" pour appeler ces fonctions
 * sans connaître OpenSSL ni les sockets POSIX.
 *
 * Utilisation typique (côté implant / client) :
 *   cfg_load(".env");
 *   tls_init();
 *   tls_conn *c = tls_connect(cfg_get("SERVER_IP", "127.0.0.1"), cfg_port());
 *   tls_send(c, "hello", 5);
 *   tls_close(c);
 *   tls_cleanup();
 */

#ifndef TLS_H
#define TLS_H

#include <stddef.h>

/* ---------- Configuration (.env) ---------- */
int         cfg_load(const char *path);
const char *cfg_get(const char *key, const char *def);
int         cfg_port(void);

/* ---------- Connexion TLS ---------- */

/* Type opaque : seul tls.c connaît le contenu réel de la structure. */
typedef struct tls_conn tls_conn;

int  tls_init(void);     /* 0 si OK ; à appeler une fois au démarrage       */
void tls_cleanup(void);  /* à appeler une fois à la fin                      */

/* Client : se connecte à ip:port, vérifie le certificat serveur (mTLS).   */
tls_conn *tls_connect(const char *ip, int port);

/* Serveur : écoute sur ip:port, accepte UN client (mTLS).                 */
tls_conn *tls_accept_one(const char *ip, int port);

/* Envoie / reçoit des octets chiffrés. Retour : nb octets, ou <= 0 si erreur. */
int tls_send(tls_conn *c, const void *data, int len);
int tls_recv(tls_conn *c, void       *buf,  int max);

/* Version TLS négociée : "TLSv1.3" ou "TLSv1.2". */
const char *tls_version(tls_conn *c);

/* Ferme la connexion et libère toute la mémoire. */
void tls_close(tls_conn *c);

#endif /* TLS_H */
