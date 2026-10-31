/*
 * addition.c — Un petit programme pour découvrir le langage C.
 *
 * Il demande deux nombres entiers, vérifie les saisies,
 * puis affiche leur somme.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

/* Lit une ligne et la convertit en int sans accepter de texte parasite. */
static int lire_entier(const char *message, int *resultat)
{
    char ligne[128];
    char *fin;
    long valeur;
    size_t longueur;
    int caractere;

    printf("%s", message);

    /* fgets limite la lecture à la taille du tableau. */
    if (fgets(ligne, sizeof(ligne), stdin) == NULL)
        return 0;

    longueur = strlen(ligne);

    /* Ne pas accepter silencieusement une ligne coupée en plusieurs lectures. */
    if (longueur == sizeof(ligne) - 1 && ligne[longueur - 1] != '\n') {
        caractere = getchar();
        if (caractere != EOF) {
            while (caractere != '\n' && caractere != EOF)
                caractere = getchar();
            return 0;
        }
    }

    errno = 0;
    valeur = strtol(ligne, &fin, 10);

    /* Aucune conversion, nombre trop grand ou valeur hors de l'intervalle int. */
    if (fin == ligne || errno == ERANGE || valeur < INT_MIN || valeur > INT_MAX)
        return 0;

    /* Après le nombre, seuls des espaces et la fin de ligne sont acceptés. */
    while (*fin == ' ' || *fin == '\t' || *fin == '\r' || *fin == '\n')
        fin++;
    if (*fin != '\0')
        return 0;

    *resultat = (int)valeur;
    return 1;
}

int main(void)
{
    int premier;
    int deuxieme;

    if (!lire_entier("Premier entier : ", &premier)) {
        fprintf(stderr, "Saisie invalide pour le premier entier.\n");
        return 1;
    }

    if (!lire_entier("Deuxieme entier : ", &deuxieme)) {
        fprintf(stderr, "Saisie invalide pour le deuxieme entier.\n");
        return 1;
    }

    /* Vérifie que l'addition ne dépasse pas la capacité d'un int. */
    if ((deuxieme > 0 && premier > INT_MAX - deuxieme) ||
        (deuxieme < 0 && premier < INT_MIN - deuxieme)) {
        fprintf(stderr, "La somme depasse la plage autorisee pour int.\n");
        return 1;
    }

    printf("Somme : %d\n", premier + deuxieme);
    return 0;
}
