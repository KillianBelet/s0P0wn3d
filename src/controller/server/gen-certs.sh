#!/usr/bin/env bash
# gen-certs.sh — Génère les certificats mTLS pour le C2 et l'implant.
#
# Usage : ./gen-certs.sh [IP_C2]   (défaut : 127.0.0.1)
# Les fichiers sont créés dans ./certs/ (exclus du dépôt via .gitignore).
#
# Prérequis : openssl (sudo apt install openssl)

set -euo pipefail

C2_IP="${1:-127.0.0.1}"
DAYS=365
DIR="$(dirname "$0")/certs"

mkdir -p "$DIR"
cd "$DIR"

echo "[*] Génération de la CA..."
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" \
    -keyout ca.key -out ca.crt \
    -subj "/CN=C2 CA"

echo "[*] Génération du certificat serveur (C2) — SAN = IP:${C2_IP}..."
openssl req -newkey rsa:2048 -nodes \
    -keyout server.key -out server.csr \
    -subj "/CN=c2-server"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "$DAYS" -out server.crt \
    -extfile <(printf "subjectAltName=IP:%s\nextendedKeyUsage=serverAuth" "$C2_IP")
rm server.csr

echo "[*] Génération du certificat client (implant)..."
openssl req -newkey rsa:2048 -nodes \
    -keyout client.key -out client.csr \
    -subj "/CN=implant"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "$DAYS" -out client.crt \
    -extfile <(printf "extendedKeyUsage=clientAuth")
rm client.csr

echo "[+] Certificats générés dans $DIR"
echo "    ca.crt      → distribuer au C2 et à l'implant"
echo "    server.crt/key → C2 uniquement"
echo "    client.crt/key → implant uniquement"
echo ""
echo "ATTENTION : ne jamais committer les fichiers *.key !"
