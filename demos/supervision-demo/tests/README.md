# Banc indépendant de supervision

Banc boîte noire Python **stdlib** : lance la CLI, observe ses lignes JSON et les processus qu'il crée. Aucun import du démonstrateur, aucun réseau, aucun bureau piloté, aucune écriture dans le démonstrateur original. Les seuls fichiers copiés pour un test négatif sont `supervisor.py` et un worker factice créé dans un répertoire temporaire du banc.

## Exécution

Depuis la racine du projet :

```powershell
python tests/run_tests.py --demo .
```

Un cas seul / un emplacement de traces distinct :

```powershell
python tests/run_tests.py --demo . --test test_killed_worker_reserved_code_never_restarts --output tests/_artifacts/kill-check
```

`--demo` désigne le **dossier** contenant `supervisor.py` et `worker.py`. `--test` peut être répété. Le runner retourne 0 uniquement si tous les tests non ignorés passent et qu'aucun nettoyage forcé n'a été nécessaire ; sinon 1. Arguments du runner invalides : 2. Les tests fonctionnels généraux sont portables ; les handles de processus, Ctrl+Break et l'erreur de chemin sont vérifiés sous Windows, sinon explicitement ignorés.

## Contrat vérifié

| Point | Attente |
|---|---|
| Arguments | `--simulate-failures` 0..4, `--max-restarts` 0..3, `--steps` 1..50, `--step-ms` 10..200, `--retry-delay-ms` 0..1000, `--deadline-seconds` 0.1..30 fini, `--stop-file` facultatif |
| Valeurs invalides | Code 2, aucun worker ; bornes inférieures/supérieures, NaN, ±inf et chaîne invalide testés |
| Calcul | Somme de 1..steps, `progress.total` = somme cumulée et non nombre de pas |
| Relance autorisée | Tentative simulée + marqueur `simulated_failure` au pas `min(3,steps)` + sortie 75 |
| Relances bornées | Au maximum `max_restarts`, tentative initiale numérotée 1, `restart_scheduled.attempt` = suivante |
| Arrêt explicite | STOP préexistant : aucun worker ; STOP actif/backoff : `stopped`/`stop_file`, 0 et aucune relance |
| Mort du parent | Worker vérifié vivant avant kill du parent, puis mort avant cleanup via fermeture du tube privé |
| Kill du worker | TerminateProcess avec le code **75**, avant marqueur : `failed`/`unexpected_exit`, 1, aucune relance |
| Échéance | En activité et en backoff : `stopped`/`deadline`, 124, aucun worker survivant |
| Signal | Ctrl+Break au groupe du superviseur de test : `stopped`/`signal`, 130 |
| Isolation | Deux superviseurs simultanés, PID workers différents, STOP du premier sans effet sur la somme du second |
| Protocole cassé | Copie isolée, worker factice écrivant une ligne non JSON : `failed`/`protocol_error`, 1 |
| Erreur I/O | Sous Windows, chemin STOP contenant `<` : `failed`/`io_error`, 1 et aucun worker |
| Témoin négatif | Faux superviseur isolé annonçant `completed.result=999` : l'oracle doit lever une assertion |

Sortie attendue : un objet JSON par ligne avec `event`. Événements du contrat : `supervisor_started`, `worker_started(pid, attempt)`, `worker_ready(pid, attempt)`, `progress(attempt, step, total)`, `simulated_failure(attempt)`, `worker_exited(attempt, pid, returncode)`, `restart_scheduled(attempt, delay_ms)`, puis un unique terminal `completed(result, attempts)`, `stopped(reason)` ou `failed(reason)`. Les champs supplémentaires sont acceptés. Le banc n'impose pas de cadence temps réel et ne fait pas de benchmark.

## Sécurité et nettoyage

- Tous les `Popen` utilisent `stdin=DEVNULL`. Attentes de processus/événements bornées, workers de test eux-mêmes bornés. Aucun programme interactif.
- `finally` nettoie les processus et répertoires temporaires de chaque cas, même en cas d'assertion.
- Sous Windows, les handles sont ouverts au moment de `worker_started`, puis leur PID et leur PID parent sont vérifiés par `NtQueryInformationProcess`. Un handle conservé empêche de tuer un autre processus si le numéro est réutilisé. Aucun scan ni kill par nom.
- Le Ctrl+Break passe par `console_bridge.py`, démarré avec `CREATE_NEW_CONSOLE` et `SW_HIDE`. Le bridge vérifie qu'il est seul dans cette console, lance le superviseur avec `CREATE_NEW_PROCESS_GROUP`, puis appelle `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid_supervisor)`. Aucun `AttachConsole`, aucune diffusion au groupe 0, aucun accès à la console de l'utilisateur. Si la console privée n'est pas disponible, cas explicitement ignoré.
- Un nettoyage forcé rend le test et le bilan global rouges : la disparition réelle du worker ne peut pas être masquée par le nettoyage.
- Le cas parent tué vérifie la mort du worker **avant** cleanup. Le cas worker tué teste volontairement le code réservé pour détecter une implémentation qui relancerait sur code seul.

## Traces et limites

`_artifacts/summary.json` contient les résultats, SHA-256 des deux sources testées, environnement et nettoyages forcés. Chaque sous-processus produit une trace `trace-*.json`, limitée à 512 lignes JSON de 4096 caractères et 8192 caractères stderr. Le résumé d'une erreur est borné à 6000 caractères. Les relances du banc ajoutent de nouveaux fichiers (pas d'effacement implicite des preuves précédentes) ; `--output` permet de séparer les campagnes.

Le banc n'audite pas statiquement l'absence de réseau/persistance et ne couvre pas toutes les courses d'ordonnancement, les permissions ACL possibles, ni une sortie stdout volontairement bloquée. Les réglages par défaut du STOP ne sont pas utilisés, afin de ne pas modifier un STOP appartenant à l'utilisateur. Les assertions de non-relance portent sur les événements et handles des processus créés, sans inventaire global du système.
