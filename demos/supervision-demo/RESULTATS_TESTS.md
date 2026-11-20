# Résultats des tests — démonstrateur supervision

## Bilan

Exécution complète du banc indépendant depuis la livraison, le 2026-11-07 21:22.

| Indicateur | Valeur |
|---|---|
| Tests exécutés | 18 |
| Réussis | 18 |
| Échecs / erreurs | 0 |
| Ignorés | 0 |
| Nettoyages forcés | 0 |
| Durée | 6,6 s |
| Code de sortie | 0 |

## Commande de reproduction

Depuis la racine du projet supervision-demo :

```powershell
python tests/run_tests.py --demo . --output tests/_artifacts/verification
```

## Empreintes des sources testées

| Fichier | SHA-256 |
|---|---|
| supervisor.py | 904968b601ab13bc90cadaca875565fc8bf7ad51fd85c43f5d16428d0db914d7 |
| worker.py | 89a40060275f6db1695043c642dfd72bda0ea3953da9bc953f4a7277b36ea393 |

Ces empreintes correspondent aux fichiers livrés dans ce dépôt, vérifiées après copie et avant commit.

## Couverture

Le banc couvre les axes suivants :

- **Calcul exact** : somme de 1..steps sans panne, résultat vérifié ; progress.total = somme cumulée.
- **Panne simulée puis récupération** : une puis trois pannes programmées, relance et succès final.
- **Bornes de relance** : max-restarts 0 et 3, dépassement → échec définitif code 1.
- **Arguments invalides** : 16 sous-cas (bornes inférieures/supérieures, NaN, ±inf, chaînes non numériques) → code 2, aucun worker lancé.
- **STOP file** : préexistant (aucun worker), pendant calcul (arrêt immédiat code 0), pendant backoff (idem).
- **Mort du parent** : le worker meurt avant le cleanup du banc (fermeture du tube privé stdin).
- **Kill du worker avec code 75 réservé mais sans marqueur** : aucune relance, événement unexpected_exit.
- **Échéance** : délai dépassé en activité et en backoff → stopped/deadline, code 124, aucun worker survivant.
- **Signal console** : Ctrl+Break sur une console privée cachée → stopped/signal, code 130.
- **Isolation** : deux superviseurs simultanés, PID distincts, STOP de l'un sans effet sur l'autre.
- **Protocole cassé** : worker factice isolé écrivant du non-JSON → failed/protocol_error, code 1.
- **Erreur I/O** : chemin STOP invalide sous Windows (caractère `<`) → failed/io_error, code 1, aucun worker.
- **Témoin négatif** : oracle du banc vérifié sur un faux superviseur annonçant un résultat erroné (l'assertion lève bien).

## Limites

- Le banc est boîte noire : il observe stdout JSON et les processus, sans instrumenter le code interne.
- Les handles de processus, Ctrl+Break et l'erreur de chemin sont spécifiques à Windows ; ignorés explicitement ailleurs.
- Les traces sont limitées à 512 lignes JSON de 4096 caractères et 8192 caractères stderr par sous-processus.
- Le banc ne teste pas un redémarrage de la machine ni l'arrêt brutal de Python lui-même (kill -9 du superviseur) au-delà de la fermeture du tube.
