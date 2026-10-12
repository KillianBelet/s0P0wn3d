/*
 * tls.c - Implémentation du module TLS (voir tls.h).
 * Toute la logique OpenSSL + Winsock est ici, et nulle part ailleurs.
 *
 * RAPPEL DES COUCHES :
 *   - TCP (Winsock)  : transporte des octets entre deux machines, EN CLAIR.
 *   - TLS (OpenSSL)  : se pose au-dessus de TCP et ajoute :
 *       * confidentialité (chiffrement),
 *       * intégrité (on détecte toute modification),
 *       * authentification (certificats signés par une CA de confiance).
 */

/* winsock2.h DOIT être inclus avant windows.h, sinon conflit avec
 * l'ancienne version winsock.h que windows.h inclut tout seul. */
#include <openssl/err.h> /* ERR_print_errors_fp : affiche les erreurs OpenSSL */
#include <openssl/ssl.h> /* SSL_CTX, SSL, SSL_connect, SSL_read... */
#include <stdio.h>       /* printf, fprintf, fopen_s, fgets */
#include <stdlib.h>      /* calloc, free, strtol */
#include <string.h>      /* strlen, strchr, strcmp, memset, strncpy_s */
#include <windows.h>     /* GetEnvironmentVariableA, DWORD */
#include <winsock2.h>    /* sockets Windows : socket, connect, bind, accept... */
#include <ws2tcpip.h>    /* inet_pton (conversion texte "127.0.0.1" -> binaire) */

/* applink.c : nécessaire sous Windows pour qu'OpenSSL écrive dans stderr.
 * Inclus UNE seule fois dans tout le programme : ici.
 * Ce fichier vient d'OpenSSL et génère des warnings (4152, 4996) ; comme on
 * compile en /WX (warning = erreur), on les désactive juste autour de lui :
 * push = sauvegarde l'état, disable = coupe, pop = restaure. */
#pragma warning(push)
#pragma warning(disable : 4152 4996)
#include <openssl/applink.c>
#pragma warning(pop)

#include "tls.h" /* nos propres déclarations : le compilateur vérifie la cohérence */

/* ====================== Configuration (.env) ====================== */

#define CFG_MAX 64     /* nombre maximum de lignes CLE=valeur retenues */
#define CFG_KEYLEN 64  /* taille max d'une clé (avec le '\0' final) */
#define CFG_VALLEN 256 /* taille max d'une valeur (avec le '\0' final) */

/* Tableau global des paires clé/valeur lues dans .env.
 * "static" au niveau fichier = visible UNIQUEMENT dans tls.c (variable privée).
 * Struct anonyme : on n'a besoin de ce type qu'ici, pas besoin de le nommer. */
static struct {
    char key[CFG_KEYLEN];
    char val[CFG_VALLEN];
} g_cfg[CFG_MAX];
static int g_cfg_count = 0;        /* nombre de cases réellement remplies */
static char g_env_buf[CFG_VALLEN]; /* tampon pour les variables d'environnement */

/* trim : enlève les espaces/tabulations au début, et les espaces/fins de
 * ligne (\r \n) à la fin. Modifie la chaîne SUR PLACE et renvoie un
 * pointeur vers le premier caractère utile. */
static char *trim(char *s) {
    char *end;
    /* Avance le pointeur tant qu'on voit un espace ou une tabulation. */
    while (*s == ' ' || *s == '\t')
        s++;
    /* end pointe juste APRÈS le dernier caractère (sur le '\0'). */
    end = s + strlen(s);
    /* Recule tant que le caractère précédent (end[-1]) est un blanc :
     * on le remplace par '\0', ce qui raccourcit la chaîne.
     * "*--end" = on recule d'abord end, puis on écrit à cet endroit. */
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
        *--end = '\0';
    return s;
}

/* Lit le fichier .env ligne par ligne et remplit g_cfg. */
int cfg_load(const char *path) {
    FILE *f = NULL;
    /* Une ligne = clé + '=' + valeur + marge (espaces, \r\n, '\0'). */
    char line[CFG_KEYLEN + CFG_VALLEN + 8];

    /* fopen_s : version "sécurisée" de fopen exigée par MSVC.
     * Retourne 0 si succès. Fichier absent => -1, on gardera les défauts. */
    if (fopen_s(&f, path, "r") != 0 || f == NULL)
        return -1;

    /* fgets lit au plus sizeof(line)-1 caractères : pas de débordement.
     * On s'arrête aussi si le tableau g_cfg est plein. */
    while (fgets(line, sizeof(line), f) != NULL && g_cfg_count < CFG_MAX) {
        char *eq, *k, *v;
        size_t vl;
        k = trim(line);
        if (*k == '\0' || *k == '#')
            continue;        /* vide ou commentaire */
        eq = strchr(k, '='); /* cherche le premier '=' */
        if (!eq)
            continue; /* ligne invalide : ignorée */
        /* Astuce : on remplace '=' par '\0' => la ligne est coupée en
         * deux chaînes : k = la clé, eq+1 = la valeur. */
        *eq = '\0';
        k = trim(k);
        v = trim(eq + 1);
        vl = strlen(v); /* retire des "guillemets" */
        /* Si la valeur commence ET finit par le même guillemet (" ou '),
         * on efface le dernier et on saute le premier. */
        if (vl >= 2 && (v[0] == '"' || v[0] == '\'') && v[vl - 1] == v[0]) {
            v[vl - 1] = '\0';
            v++;
        }
        /* Copie sécurisée : _TRUNCATE coupe proprement si c'est trop long
         * au lieu de déborder du tableau. */
        strncpy_s(g_cfg[g_cfg_count].key, CFG_KEYLEN, k, _TRUNCATE);
        strncpy_s(g_cfg[g_cfg_count].val, CFG_VALLEN, v, _TRUNCATE);
        g_cfg_count++;
    }
    fclose(f); /* toujours fermer un fichier ouvert */
    return 0;
}

/* Cherche la valeur d'une clé : 1) .env  2) variable d'environnement  3) défaut. */
const char *cfg_get(const char *key, const char *def) {
    int i;
    DWORD n; /* DWORD = entier non signé 32 bits de Windows */
    /* On parcourt à l'envers : si une clé apparaît deux fois dans .env,
     * c'est la dernière définition qui gagne. */
    for (i = g_cfg_count - 1; i >= 0; i--)
        if (strcmp(g_cfg[i].key, key) == 0)
            return g_cfg[i].val; /* strcmp == 0 => égales */
    /* Pas dans .env : on demande à Windows. Retour = longueur copiée ;
     * 0 = variable absente ; >= taille du tampon = tampon trop petit. */
    n = GetEnvironmentVariableA(key, g_env_buf, (DWORD)sizeof(g_env_buf));
    if (n > 0 && n < sizeof(g_env_buf))
        return g_env_buf;
    return def; /* ni l'un ni l'autre : valeur par défaut */
}

/* Lit SERVER_PORT et le convertit en entier, avec validation. */
int cfg_port(void) {
    /* strtol convertit du texte en long, en base 10. Texte invalide => 0. */
    long p = strtol(cfg_get("SERVER_PORT", "12345"), NULL, 10);
    /* Un port TCP valide est entre 1 et 65535 ; sinon on revient au défaut. */
    return (p > 0 && p <= 65535) ? (int)p : 12345;
}

/* ====================== TLS ====================== */

/* Définition RÉELLE du type opaque annoncé dans tls.h.
 * Une connexion = 3 éléments :
 *   ctx  : le CONTEXTE (configuration : certificats, CA, version min...)
 *   ssl  : la SESSION TLS (état du chiffrement pour CETTE connexion)
 *   sock : le socket TCP en dessous qui transporte les octets chiffrés */
struct tls_conn {
    SSL_CTX *ctx;
    SSL *ssl;
    SOCKET sock;
};

/* Démarre Winsock : obligatoire sous Windows avant tout appel réseau.
 * MAKEWORD(2, 2) = on demande la version 2.2 de Winsock. */
int tls_init(void) {
    WSADATA wsa; /* WSAStartup y écrit des infos (inutilisées ici) */
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? 0 : -1;
}

/* Arrête Winsock (pendant de WSAStartup). */
void tls_cleanup(void) { WSACleanup(); }

/* Libère tout, dans l'ordre INVERSE de la création.
 * Chaque champ est testé : la fonction marche même sur une connexion
 * à moitié construite (c'est pour ça qu'on l'utilise aussi dans "fail:"). */
void tls_close(tls_conn *c) {
    if (!c)
        return; /* tls_close(NULL) ne fait rien : appel toujours sûr */
    /* SSL_shutdown envoie l'alerte "close_notify" : l'autre côté sait que
     * la fin est volontaire (et pas une coupure / attaque de troncature). */
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    if (c->sock != INVALID_SOCKET)
        closesocket(c->sock);
    if (c->ctx)
        SSL_CTX_free(c->ctx);
    free(c); /* enfin, la structure elle-même (allouée par calloc) */
}

/* Crée le contexte commun : TLS 1.2 minimum, notre certificat, la CA de confiance,
 * et vérification obligatoire du certificat d'en face.
 *   server : 1 pour le serveur, 0 pour le client
 *   cert   : chemin de NOTRE certificat (clé publique signée par la CA)
 *   key    : chemin de NOTRE clé privée (ne doit jamais quitter la machine) */
static SSL_CTX *make_ctx(int server, const char *cert, const char *key) {
    /* La CA (autorité de certification) : on fait confiance à tout
     * certificat signé par elle, et à rien d'autre. */
    const char *ca = cfg_get("CA_CERT", "certs/ca.crt");
    /* Méthode serveur ou client selon le rôle (TLS_*_method = négocie la
     * meilleure version supportée par les deux côtés). */
    SSL_CTX *ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    /* Chaque fonction renvoie 1 si succès. Grâce au "||" (évaluation
     * court-circuit), on s'arrête à la PREMIÈRE qui échoue. */
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1 /* refuse TLS 1.0/1.1, obsolètes */
        || SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1    /* charge la CA de confiance */
        || SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1 /* notre certificat */
        || SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1   /* notre clé privée */
        || SSL_CTX_check_private_key(ctx) != 1) { /* clé et certificat vont ensemble ? */
        fprintf(stderr, "Certificats invalides (CA=%s, cert=%s, cle=%s)\n", ca, cert, key);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx); /* on libère avant de sortir : pas de fuite mémoire */
        return NULL;
    }
    /* Vérification du certificat d'en face :
     *  - SSL_VERIFY_PEER : on vérifie le certificat de l'autre côté.
     *  - Côté serveur, + SSL_VERIFY_FAIL_IF_NO_PEER_CERT : un client SANS
     *    certificat est REJETÉ => authentification mutuelle (mTLS).
     *  - NULL : pas de fonction de rappel, on garde la vérification standard. */
    SSL_CTX_set_verify(
        ctx, server ? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT) : SSL_VERIFY_PEER, NULL);
    return ctx;
}

/* Alloue une connexion vide.
 * calloc (et pas malloc) : met tout à zéro => ctx et ssl valent NULL,
 * ce qui permet à tls_close de savoir ce qui a été créé ou non. */
static tls_conn *new_conn(void) {
    tls_conn *c = (tls_conn *)calloc(1, sizeof(*c));
    /* 0 n'est pas "pas de socket" sous Windows : on met la vraie valeur. */
    if (c)
        c->sock = INVALID_SOCKET;
    return c;
}

/* Remplit une adresse IPv4 (struct sockaddr_in) à partir du texte "ip" et du port. */
static int make_addr(const char *ip, int port, struct sockaddr_in *a) {
    memset(a, 0, sizeof(*a)); /* tout à zéro pour ne pas laisser de déchets */
    a->sin_family = AF_INET;  /* IPv4 */
    /* htons = "host to network short" : le réseau utilise l'ordre
     * big-endian, alors que le PC (x86) est little-endian. */
    a->sin_port = htons((u_short)port);
    /* inet_pton : texte "127.0.0.1" -> 4 octets binaires. Retour 1 = OK. */
    if (inet_pton(AF_INET, ip, &a->sin_addr) != 1) {
        fprintf(stderr, "Adresse IP invalide : %s\n", ip);
        return -1;
    }
    return 0;
}

/* CÔTÉ CLIENT : TCP connect puis handshake TLS. */
tls_conn *tls_connect(const char *ip, int port) {
    struct sockaddr_in addr;
    tls_conn *c;

    if (make_addr(ip, port, &addr) != 0)
        return NULL;
    c = new_conn();
    if (!c)
        return NULL;

    /* 1) Contexte client avec NOTRE certificat client (mTLS). */
    c->ctx = make_ctx(0, cfg_get("CLIENT_CERT", "certs/client.crt"),
                      cfg_get("CLIENT_KEY", "certs/client.key"));
    if (!c->ctx)
        goto fail;
    /* 2) Une session TLS issue de ce contexte. */
    c->ssl = SSL_new(c->ctx);
    /* le certificat serveur doit contenir cette IP (anti-usurpation) :
     * sans ça, n'importe quel serveur ayant un certificat signé par la CA
     * pourrait se faire passer pour celui-ci (attaque "man-in-the-middle"). */
    if (!c->ssl || SSL_set1_ipaddr(c->ssl, ip) != 1) {
        ERR_print_errors_fp(stderr);
        goto fail;
    }

    /* 3) Connexion TCP classique (SOCK_STREAM + IPPROTO_TCP = TCP). */
    c->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c->sock == INVALID_SOCKET ||
        connect(c->sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "Connexion a %s:%d impossible (%d)\n", ip, port, WSAGetLastError());
        goto fail;
    }
    /* 4) On attache la session TLS au socket, puis HANDSHAKE :
     *    échange des certificats, vérification par la CA, négociation de
     *    la version et des clés de chiffrement. Retour 1 = réussi. */
    if (SSL_set_fd(c->ssl, (int)c->sock) != 1 || SSL_connect(c->ssl) != 1) {
        /* Affiche la raison lisible (ex. "certificate has expired"). */
        fprintf(stderr, "Handshake TLS echoue : %s\n",
                X509_verify_cert_error_string(SSL_get_verify_result(c->ssl)));
        ERR_print_errors_fp(stderr);
        goto fail;
    }
    return c; /* succès : connexion chiffrée et authentifiée */

/* Point de sortie unique en cas d'erreur : "goto fail" évite de répéter
 * le nettoyage partout. tls_close libère ce qui a été créé jusque-là. */
fail:
    tls_close(c);
    return NULL;
}

/* CÔTÉ SERVEUR : bind + listen + accept (un seul client), puis handshake TLS. */
tls_conn *tls_accept_one(const char *ip, int port) {
    struct sockaddr_in addr;
    SOCKET listener; /* socket d'ÉCOUTE (distinct du socket de dialogue) */
    tls_conn *c;

    if (make_addr(ip, port, &addr) != 0)
        return NULL;
    c = new_conn();
    if (!c)
        return NULL;

    /* 1) Contexte serveur avec le certificat serveur. */
    c->ctx = make_ctx(1, cfg_get("SERVER_CERT", "certs/server.crt"),
                      cfg_get("SERVER_KEY", "certs/server.key"));
    if (!c->ctx)
        goto fail;

    /* 2) socket = crée ; bind = l'attache à ip:port ;
     *    listen = se met en attente (1 = file d'attente d'1 client). */
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET || bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listener, 1) != 0) {
        fprintf(stderr, "bind/listen sur %s:%d a echoue (%d)\n", ip, port, WSAGetLastError());
        if (listener != INVALID_SOCKET)
            closesocket(listener);
        goto fail;
    }
    printf("Serveur en ecoute sur %s:%d\n", ip, port);
    fflush(stdout); /* force l'affichage tout de suite (sortie bufferisée) */
    /* 3) accept BLOQUE jusqu'à ce qu'un client se connecte ; il renvoie un
     *    NOUVEAU socket dédié à ce client. NULL, NULL = on ne veut pas
     *    connaître l'adresse du client. */
    c->sock = accept(listener, NULL, NULL);
    closesocket(listener); /* un seul client : on n'écoute plus */
    if (c->sock == INVALID_SOCKET) {
        fprintf(stderr, "accept() a echoue (%d)\n", WSAGetLastError());
        goto fail;
    }

    /* 4) Session TLS + handshake côté serveur (SSL_accept). Ici le serveur
     *    EXIGE et vérifie le certificat du client (voir make_ctx). */
    c->ssl = SSL_new(c->ctx);
    if (!c->ssl || SSL_set_fd(c->ssl, (int)c->sock) != 1 || SSL_accept(c->ssl) != 1) {
        fprintf(stderr, "Handshake TLS refuse\n");
        ERR_print_errors_fp(stderr);
        goto fail;
    }
    return c;
fail:
    tls_close(c);
    return NULL;
}

/* SSL_write chiffre les données puis les envoie dans le socket. */
int tls_send(tls_conn *c, const void *data, int len) {
    int n = SSL_write(c->ssl, data, len);
    if (n <= 0)
        ERR_print_errors_fp(stderr);
    return n;
}

/* SSL_read lit dans le socket, vérifie l'intégrité et déchiffre.
 * Retourne le nombre d'octets en clair placés dans buf (au plus max). */
int tls_recv(tls_conn *c, void *buf, int max) {
    int n = SSL_read(c->ssl, buf, max);
    if (n <= 0)
        ERR_print_errors_fp(stderr);
    return n;
}

/* Version de TLS négociée pendant le handshake. */
const char *tls_version(tls_conn *c) { return SSL_get_version(c->ssl); }
