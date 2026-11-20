#ifndef SHELL_H
#define SHELL_H

/*
** shell.h — Module shell built-in natif (ticket #38)
**
** Exécute des commandes système via l'API Win32 directement,
** sans spawn de cmd.exe ni PowerShell. Chaque commande retourne
** une chaîne allouée (malloc) terminée par '\0', à libérer par
** l'appelant via free(). Retourne NULL si commande inconnue.
*/

/* Taille maximale d'une réponse du module shell (64 Ko). */
#define SHELL_BUFFER_SIZE 65536

/*
** Point d'entrée du module : exécute une commande built-in.
** `input` contient la commande SANS le préfixe "sh " (ex: "ls C:\").
** Retourne une chaîne malloc-ée (à free() par l'appelant) ou NULL
** si la commande n'est pas reconnue.
*/
char *shell_execute(const char *input);

#endif /* !SHELL_H */
