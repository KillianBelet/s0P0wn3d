## Élévation de privilèges, multi-client, refonte C2 et nettoyage du projet

### Résumé

Cette branche implémente l'élévation de privilèges par UAC bypass (T1548.002), ajoute le support multi-client au C2, l'exécution PowerShell, le mode standalone avec certificats embarqués, et réorganise entièrement l'arborescence du projet.

### Fonctionnalités ajoutées

**Élévation de privilèges — UAC Bypass via fodhelper.exe (T1548.002)**
- L'implant s'auto-élève en administrateur sans déclencher le prompt UAC
- Exploitation de la clé `HKCU\Software\Classes\ms-settings\Shell\Open\command`
- Commande `elevate` : auto-détection du chemin (GetModuleFileNameA), écriture registre, lancement fodhelper (ShellExecuteExA, fenêtre cachée), nettoyage des clés
- Commande `privesc <path>` : UAC bypass manuel avec un exe spécifié
- Le C2 détecte automatiquement la session élevée et switch dessus

**C2 multi-client (pthreads)**
- Thread d'écoute (`accept_thread`) en arrière-plan acceptant plusieurs implants simultanément
- Gestion de sessions : `sessions`/`list`, `use <id>`, `bg`/`background`, `close`
- Auto-entrée dans la première session connectée
- La commande `elevate` utilise un appel récursif à `interact()` pour switcher sur la session admin

**Exécution PowerShell (T1059.001)**
- Commande `ps <cmd>` dans le shell interactif
- Flags : `-NoProfile -NonInteractive -ExecutionPolicy Bypass`

**Mode standalone — certificats embarqués**
- `make embed` génère `embedded_certs.h` depuis `certs/` (tableaux d'octets)
- `make implant-standalone` compile avec `-DEMBED_CERTS` : zéro dépendance sur la cible
- Chargement des certs via `BIO_new_mem_buf` (OpenSSL) au lieu de fichiers

**Implant sans fenêtre (T1036)**
- Flag `-mwindows` en production : aucune fenêtre visible
- Target `make implant-debug` séparée avec console pour les tests

### Refactoring & nettoyage

**Réorganisation de l'arborescence**
- Implant déplacé : `src/controller/server/implant.c` → `src/implant/implant.c`
- Privesc déplacé : `src/controller/server/privesc.c/h` → `src/implant/privesc.c/h`
- Makefile mis à jour avec `IMPLANT_DIR = ../../implant` et flags `-I`

**Suppression du code obsolète**
- `c2_server.py` + `requirements.txt` (ancien C2 Python, remplacé par C)
- `tls-demo/` (prototype TLS, intégré dans le code final)
- `src/implant/core/` (ancien implant Phase 1 : aes.c, crypto.c, shell.c, main.c)
- `src/implant/payloads/elevate.c` (ancienne DLL PrintNightmare)

**Corrections**
- IPs harmonisées partout : C2 = `192.168.56.101`, Target = `192.168.56.102`
- `.env.example` mis à jour avec la bonne IP

### Documentation (README)

- Section **Arborescence** : structure complète du projet avec rôle de chaque fichier
- Section **Élévation de privilèges** : principe, étapes de l'attaque, prérequis, procédure de test pas à pas (7 étapes), indicateurs Blue Team
- Section **Mode standalone** : procédure de compilation en 3 étapes
- Section **Troubleshooting** : 7 problèmes courants avec solutions
- Tables de commandes complètes (menu principal + session)
- Table **MITRE ATT&CK** mise à jour : T1059.003, T1059.001, T1573.001, T1036, T1548.002
- Persistance (T1547.001) marquée "à réimplémenter"
- Commentaires complets dans tous les fichiers source (tls.c, privesc.c, implant.c, c2_server.c, Makefile)

### MITRE ATT&CK

| Technique | ID | Statut |
|---|---|---|
| Windows Command Shell | T1059.003 | ✅ Implémenté |
| PowerShell | T1059.001 | ✅ Implémenté |
| Encrypted Channel (mTLS) | T1573.001 | ✅ Implémenté |
| Masquerading (-mwindows) | T1036 | ✅ Implémenté |
| Bypass UAC (fodhelper) | T1548.002 | ✅ Implémenté |
| Registry Run Keys | T1547.001 | 📋 À réimplémenter |

### Test plan

- [ ] Compiler le C2 (`make server`) sur Ubuntu et vérifier le lancement
- [ ] Compiler l'implant en debug (`make implant-debug`) sur Windows (MSYS2 MINGW64)
- [ ] Vérifier la connexion mTLS entre implant et C2
- [ ] Tester les commandes cmd.exe et PowerShell (`ps whoami`)
- [ ] Tester `elevate` : vérifier l'élévation avec `whoami /priv`
- [ ] Tester la navigation multi-session (`bg`, `sessions`, `use <id>`, `close`)
- [ ] Compiler la version production (`make implant`) et vérifier l'absence de fenêtre
- [ ] Vérifier le chiffrement avec tcpdump (`strings` ne doit rien révéler)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
