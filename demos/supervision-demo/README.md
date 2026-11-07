# Démonstrateur de récupération après panne

Python standard library, calcul fixé **somme de 1 à steps**. Le superviseur est visible et ne lance que le worker livré à côté de lui. Il n'accepte aucune commande à exécuter. Ce démonstrateur est indépendant du projet C et n'est pas un mécanisme anti-arrêt.

## Exécution

Depuis la racine de l'espace de travail :

```powershell
python .\supervision-demo\supervisor.py
python .\supervision-demo\supervisor.py --simulate-failures 0 --steps 10
```

Par défaut, la première tentative échoue volontairement au troisième pas ; la suivante calcule 55. Les événements JSON Lines sont écrits sur stdout, immédiatement vidés, avec un temps monotone relatif en millisecondes. Les erreurs d'arguments sont sur stderr.

| Option | Valeurs admises | Défaut |
|---|---|---|
| --simulate-failures | entier 0..4 | 1 |
| --max-restarts | entier 0..3 | 2 |
| --steps | entier 1..50 | 10 |
| --step-ms | entier 10..200 | 100 |
| --retry-delay-ms | entier 0..1000 | 200 |
| --deadline-seconds | nombre fini 0.1..30 (NaN/inf refusés) | 10 |
| --stop-file | chemin de l'indicateur d'arrêt | STOP à côté de supervisor.py |

Un chemin explicite relatif est interprété depuis le dossier courant. Le STOP par défaut reste à côté du script, indépendamment du dossier courant. Le programme ne crée ni ne supprime cet indicateur.

## Arrêter

Ctrl+C (ou Ctrl+Break sous Windows), ou créer l'indicateur d'arrêt depuis un autre terminal :

```powershell
New-Item -ItemType File .\supervision-demo\STOP
```

Un indicateur présent avant le départ empêche tout lancement de worker. Pendant le calcul ou l'attente de relance, sa présence termine le programme. Il faut le retirer explicitement pour permettre une prochaine exécution :

```powershell
Remove-Item .\supervision-demo\STOP
```

Utiliser des chemins --stop-file différents pour deux exécutions indépendantes ; le STOP par défaut est volontairement commun aux exécutions du même dossier.

## Pourquoi ces choix

- **Une seule direction de supervision** : le worker ne lance aucun processus, et ne recrée jamais son parent.
- **EOF sur un tube stdin privé** : le superviseur est seul à posséder l'extrémité d'écriture. Sa disparition ferme le tube ; le worker interrompt son calcul. Aucun PID à retrouver ni processus extérieur à surveiller.
- **Relances strictement limitées** : au plus trois relances, et seulement si la tentative était programmée comme simulée, si le protocole attendu a été observé jusqu'au marqueur simulated_failure, puis si le code de sortie est 75. Une sortie inconnue, un résultat absent ou un worker tué sans ce marqueur n'est jamais relancé. Chaque tentative recommence la somme depuis zéro.
- **Arrêt prioritaire** : signal, indicateur STOP et échéance sont vérifiés pendant le calcul et le délai, puis avant chaque nouvelle tentative. Le superviseur ferme le tube et attend la fin de son propre worker ; il ne termine aucun autre processus.
- **Protocole vérifié** : ordre des étapes, somme cumulée, PID prêt et résultat final sont contrôlés, pas seulement le code de sortie. Les booléens JSON ne sont pas acceptés à la place d'entiers.

Le worker émet le marqueur de panne au pas min(3, steps). Un kill externe avec code 75 **sans marqueur** n'est donc pas assimilé à une panne simulée. Ce protocole n'est pas une preuve cryptographique de la cause d'une terminaison : un environnement qui remplace les fichiers, ou forge exactement le protocole et le code de sortie, n'est pas un scénario de confiance pris en charge.

## Événements et codes de sortie

| Événement | Champs utiles (outre elapsed_ms) |
|---|---|
| supervisor_started | pid, stop_file, max_restarts |
| worker_started / worker_ready | pid, attempt (à partir de 1) |
| progress | attempt, step, total (somme cumulée) |
| simulated_failure | attempt |
| worker_exited | attempt, pid, returncode |
| restart_scheduled | attempt (tentative suivante), delay_ms |
| completed | result, attempts |
| stopped | reason : stop_file, signal ou deadline |
| failed | reason : restart_limit, unexpected_exit, protocol_error ou io_error |

Codes : **0** succès ou stop_file ; **130** signal traité ; **124** échéance ; **1** échec ; **2** arguments invalides. Un parent tué brutalement ne peut pas émettre un dernier événement ; son code est alors celui de l'OS. Le worker interne réserve **75** à la panne simulée.

## Limites explicites

- Aucun réseau, registre, démarrage automatique, service, persistance ou mode caché.
- Ce n'est pas un superviseur de programmes arbitraires, ni un outil de disponibilité en production.
- L'échéance est monotone, vérifiée toutes les 25 ms environ ; ce n'est pas du temps réel dur. La fermeture coopérative et le nettoyage borné peuvent ajouter du temps après l'échéance. Le système d'exploitation, la création de processus et un consommateur stdout bloqué peuvent aussi retarder le retour. stdout doit être consommé normalement.
- Le nettoyage tente d'abord l'EOF, puis termine uniquement le worker créé si nécessaire (attentes bornées). Aucun traitement n'empêche la terminaison forcée des processus.
- Le contrat porte sur la présence observée de STOP : conserver le fichier jusqu'à l'arrêt plutôt que le créer et le supprimer immédiatement.
- Les résultats vérifiés et les limites de plateforme sont détaillés dans RESULTATS_TESTS.md.
