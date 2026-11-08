#!/bin/bash
# gen-embed.sh — Génère embedded_certs.h depuis les fichiers PEM du dossier certs/
# Usage : bash gen-embed.sh [certs_dir]
#
# Produit un header C avec les certificats et clés en tableaux d'octets,
# permettant de compiler un implant standalone (zéro fichier externe).

CERTS_DIR="${1:-certs}"
OUT="embedded_certs.h"

if [ ! -f "$CERTS_DIR/ca.crt" ] || [ ! -f "$CERTS_DIR/client.crt" ] || [ ! -f "$CERTS_DIR/client.key" ]; then
    echo "Erreur : fichiers ca.crt, client.crt, client.key manquants dans $CERTS_DIR/"
    exit 1
fi

file_to_array() {
    local file="$1"
    local name="$2"
    local size
    size=$(wc -c < "$file" | tr -d ' ')
    echo "static const unsigned char ${name}[] = {"
    xxd -i < "$file" | sed 's/^/    /'
    echo "};"
    echo "static const int ${name}_len = ${size};"
    echo ""
}

cat > "$OUT" <<'HEADER'
#ifndef EMBEDDED_CERTS_H
#define EMBEDDED_CERTS_H

HEADER

file_to_array "$CERTS_DIR/ca.crt"      "embed_ca_crt"      >> "$OUT"
file_to_array "$CERTS_DIR/client.crt"   "embed_client_crt"  >> "$OUT"
file_to_array "$CERTS_DIR/client.key"   "embed_client_key"  >> "$OUT"

echo "#endif /* EMBEDDED_CERTS_H */" >> "$OUT"

echo "[+] $OUT généré ($(wc -c < "$OUT" | tr -d ' ') octets)"
