/*
 * tls.h - Petit module TLS réutilisable (Windows / MSVC / OpenSSL).
 *
 * RÔLE DE CE FICHIER (le "header") :
 *   Un .h ne contient que des DÉCLARATIONS : il annonce au compilateur
 *   "ces fonctions existent, voici leurs paramètres et leur type de retour".
 *   Le code réel (les DÉFINITIONS) est dans tls.c.
 *   client.c et server.c font #include "tls.h" pour pouvoir appeler ces
 *   fonctions sans connaître leur implémentation.
 *
 * POURQUOI UN MODULE SÉPARÉ ?
 *   Le reste du projet n'utilise QUE ces fonctions : il n'a pas besoin de
 *   connaître OpenSSL ni Winsock. C'est le principe d'ENCAPSULATION :
 *   si on change de bibliothèque TLS demain, seul tls.c change.
 *
 * Utilisation typique :
 *   cfg_load(".env");            // lit la configuration
 *   tls_init();                  // démarre le réseau
 *   tls_conn *c = tls_connect(cfg_get("SERVER_IP", "127.0.0.1"), cfg_port());
 *   tls_send(c, "hello", 5);
 *   tls_close(c);
 *   tls_cleanup();
 */

/* "Include guard" : si ce fichier est inclus deux fois dans le même .c,
 * la 2e fois TLS_H est déjà défini, donc tout le contenu est sauté.
 * Ça évite les erreurs de "redéfinition". */
#ifndef TLS_H
#define TLS_H

/* stddef.h fournit des types standards comme size_t. */
#include <stddef.h>

/* ---------- Configuration (.env) ---------- */

/* Charge un fichier "CLE=valeur" (lignes vides et # ignorées).
 * Retourne 0 si OK, -1 si le fichier est absent (on garde alors les défauts).
 * "const char *" = on lit la chaîne mais on promet de ne pas la modifier. */
int cfg_load(const char *path);

/* Valeur d'une clé : .env d'abord, puis variable d'environnement Windows,
 * sinon la valeur par défaut fournie (def). */
const char *cfg_get(const char *key, const char *def);

/* Raccourci : SERVER_PORT en entier (défaut 12345).
 * "(void)" en C = la fonction ne prend AUCUN paramètre. */
int cfg_port(void);

/* ---------- Connexion TLS ---------- */

/* TYPE OPAQUE : on déclare que "struct tls_conn" existe, sans dire ce
 * qu'il y a dedans. client.c / server.c ne peuvent manipuler qu'un
 * POINTEUR (tls_conn *), jamais les champs. Le contenu réel est défini
 * uniquement dans tls.c => personne d'autre ne peut le casser.
 * Le typedef permet d'écrire "tls_conn" au lieu de "struct tls_conn". */
typedef struct tls_conn tls_conn;

int tls_init(void);     /* 0 si OK ; à appeler une fois au démarrage (démarre Winsock) */
void tls_cleanup(void); /* à appeler une fois à la fin (arrête Winsock) */

/* Client : se connecte à ip:port, vérifie le certificat du serveur
 * (signé par CA_CERT et contenant cette IP) et présente CLIENT_CERT.
 * Retourne NULL si échec (à tester systématiquement !). */
tls_conn *tls_connect(const char *ip, int port);

/* Serveur : écoute sur ip:port, attend UN client, exige son certificat
 * (authentification MUTUELLE = mTLS). NULL si échec. */
tls_conn *tls_accept_one(const char *ip, int port);

/* Envoie / reçoit des octets chiffrés. Retour : nb d'octets, ou <= 0 si erreur.
 * "const void *" = n'importe quel type de données, en lecture seule. */
int tls_send(tls_conn *c, const void *data, int len);
int tls_recv(tls_conn *c, void *buf, int max);

/* Version négociée : "TLSv1.3" ou "TLSv1.2". */
const char *tls_version(tls_conn *c);

/* Ferme proprement la connexion et libère toute la mémoire associée. */
void tls_close(tls_conn *c);

#endif /* fin de l'include guard TLS_H */
