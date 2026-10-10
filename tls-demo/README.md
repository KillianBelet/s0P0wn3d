# Client / serveur chiffrés en TLS (C, Windows, OpenSSL)

Un client envoie un message au serveur, qui répond `ECHO: <message>`.
Tout ce qui passe sur le réseau est **chiffré en TLS** (TLS 1.3 en pratique, 1.2 minimum),
et **chacun vérifie l'identité de l'autre** grâce à des certificats (on parle de « TLS mutuel »).

---

## Les fichiers, et à quoi ils servent

```
./
├── .env            ← les RÉGLAGES (IP, port, certificats) — modifiable sans recompiler
├── tls.h           ← le MODE D'EMPLOI du module TLS (la liste des fonctions disponibles)
├── tls.c           ← le MOTEUR du module TLS (tout le code compliqué OpenSSL/réseau)
├── client.c        ← l'application client (très courte, utilise tls.h)
├── server.c        ← l'application serveur (très courte, utilise tls.h)
├── build.ps1       ← compile client.exe et server.exe
├── gen-certs.ps1   ← fabrique les certificats dans certs\
└── certs\          ← certificats et clés (SECRETS : à ne jamais publier)
```

### `tls.h` — le mode d'emploi

Imaginez une télécommande : vous voyez les boutons, mais pas l'électronique.
`tls.h` est la liste des « boutons » que le reste du projet a le droit d'utiliser :

| Fonction | Ce qu'elle fait |
|---|---|
| `cfg_load(".env")` | Lit le fichier de réglages |
| `cfg_get("CLE", "défaut")` | Donne la valeur d'un réglage |
| `cfg_port()` | Donne le port (`SERVER_PORT`) |
| `tls_init()` / `tls_cleanup()` | Démarre / arrête le réseau (une fois par programme) |
| `tls_connect(ip, port)` | **Client** : se connecte au serveur de façon sécurisée |
| `tls_accept_one(ip, port)` | **Serveur** : attend un client et vérifie son certificat |
| `tls_send(c, data, len)` | Envoie des données (chiffrées automatiquement) |
| `tls_recv(c, buf, max)` | Reçoit des données (déchiffrées automatiquement) |
| `tls_version(c)` | Version utilisée : `TLSv1.3` ou `TLSv1.2` |
| `tls_close(c)` | Ferme proprement la connexion |

Un fichier `.c` qui fait `#include "tls.h"` peut utiliser ces fonctions, **sans rien savoir d'OpenSSL**.

### `tls.c` — le moteur

C'est l'électronique de la télécommande. Il contient tout ce qui est délicat :

- création des sockets Windows (Winsock) ;
- chargement des certificats et de la clé privée ;
- **TLS 1.2 minimum** imposé ;
- **vérification du certificat d'en face** (refus si signé par une autre autorité) ;
- côté client : vérification que le certificat du serveur contient **bien l'IP demandée**
  (empêche un faux serveur de se faire passer pour le vrai) ;
- côté serveur : **refus de tout client sans certificat valide** ;
- lecture du fichier `.env`.

Avantage : si un jour on corrige ou durcit la sécurité, on ne touche **qu'à ce fichier**,
et toutes les applications du projet en profitent.

### `.env` — les réglages

Un simple fichier texte `CLE=valeur`, lu au démarrage. On change l'IP ou le port
**sans recompiler** :

| Clé | Utilisée par | Rôle |
|---|---|---|
| `SERVER_IP` | client | IP du serveur à joindre |
| `SERVER_BIND_IP` | serveur | IP sur laquelle écouter (`0.0.0.0` = toutes) |
| `SERVER_PORT` | les deux | Port (doit être identique des deux côtés) |
| `CA_CERT` | les deux | Autorité de confiance (`certs/ca.crt`) |
| `SERVER_CERT` / `SERVER_KEY` | serveur | Certificat + clé privée du serveur |
| `CLIENT_CERT` / `CLIENT_KEY` | client | Certificat + clé privée du client |

Ordre de priorité pour une valeur :
1. l'argument en ligne de commande : `client.exe 192.168.76.1` ;
2. le fichier `.env` ;
3. une variable d'environnement Windows du même nom ;
4. la valeur par défaut écrite dans le code.

> Il n'y a **pas d'« IP client »** à régler : c'est Windows qui choisit l'adresse
> du client automatiquement au moment de la connexion.

---

## ⚠️ Changer l'IP du serveur = refaire son certificat

Le client vérifie que l'IP du serveur est **écrite dans le certificat du serveur**.
Actuellement le certificat contient `127.0.0.1`, `192.168.76.1` et `localhost`.

Pour utiliser une autre IP, ici `10.0.0.5` :
1. dans `gen-certs.ps1`, ajouter l'IP à la ligne `subjectAltName=IP:127.0.0.1,IP:192.168.76.1,IP:10.0.0.5,...` ;
2. relancer `.\gen-certs.ps1` ;
3. copier le **nouveau** dossier `certs\` sur les deux machines ;
4. mettre `SERVER_IP=10.0.0.5` dans le `.env`.

Sinon le client refusera la connexion : **c'est voulu**, c'est la protection contre l'usurpation.

---

## Utilisation

```powershell
.\gen-certs.ps1          # une seule fois : crée les certificats
.\build.ps1              # compile

# Terminal 1
.\server.exe             # écoute sur SERVER_BIND_IP:SERVER_PORT du .env

# Terminal 2
.\client.exe             # se connecte à SERVER_IP du .env
```

Pour lancer sur une autre machine, il faut copier à côté de l'exécutable :
`client.exe` (ou `server.exe`), les deux DLL `libssl-4-x64.dll` / `libcrypto-4-x64.dll`,
le `.env` et le dossier `certs\`.

---

## Réutiliser le TLS dans un autre projet

1. Copier `tls.c`, `tls.h`, `.env` et `certs\` dans le projet.
2. Ajouter `tls.c` à la compilation (voir la ligne `cl` de `build.ps1`) et lier
   `libssl.lib libcrypto.lib ws2_32.lib`.
3. Dans votre code :

```c
#include "tls.h"

int main(void)
{
    cfg_load(".env");
    tls_init();

    tls_conn *c = tls_connect(cfg_get("SERVER_IP", "127.0.0.1"), cfg_port());
    if (c) {
        tls_send(c, "bonjour", 7);   /* part chiffré sur le réseau */
        tls_close(c);
    }
    tls_cleanup();
    return 0;
}
```

---

## Chiffrement vérifié

Une capture des octets réellement transmis entre le client et le serveur montre :

- version négociée : **TLSv1.3**, client authentifié par le serveur ;
- **le texte du message n'apparaît nulle part** dans la capture ;
- seul le premier paquet (« ClientHello », la prise de contact) est lisible.
  Tout le reste est de l'« Application Data » chiffrée.

Pour vérifier soi-même : Wireshark, filtre `tcp.port == 12345`.

## Sécurité

- `certs\*.key` sont des **clés privées** : ne jamais les publier. Le `.gitignore` exclut
  déjà `certs/`, les `.exe`, les `.dll` et les fichiers de compilation.
- Les certificats générés par `gen-certs.ps1` sont auto-signés et valables **30 jours** :
  pensez à les régénérer, ou à allonger `-days`, avant expiration.
- Le `.env` ne contient pas de secret, seulement des chemins et des adresses.
