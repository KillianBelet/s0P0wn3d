#!/usr/bin/env bash
# setup-openssl-win.sh — Compile OpenSSL pour Windows (cross-compilation mingw-w64)
#
# À exécuter UNE SEULE FOIS sur le C2 Ubuntu avant de compiler implant.exe.
# Résultat : third_party/openssl-win64/{include/,lib/}
#
# Durée : ~3-5 minutes (compilation depuis les sources).
# Prérequis : mingw-w64, make, perl
#   sudo apt install gcc-mingw-w64 mingw-w64 perl make -y

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/third_party/openssl-win64"
OPENSSL_VER="3.3.2"
OPENSSL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz"
BUILD_DIR="/tmp/openssl-win64-build"

# --- Vérifier les prérequis ---
for cmd in x86_64-w64-mingw32-gcc perl make; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "[!] Prérequis manquant : $cmd"
        echo "    sudo apt install gcc-mingw-w64 mingw-w64 perl make -y"
        exit 1
    fi
done

if [ -f "$OUT_DIR/include/openssl/ssl.h" ] && [ -f "$OUT_DIR/lib/libssl.a" ]; then
    echo "[+] OpenSSL Windows déjà compilé dans $OUT_DIR — rien à faire."
    exit 0
fi

echo "[*] Téléchargement OpenSSL ${OPENSSL_VER}..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [ ! -f "openssl-${OPENSSL_VER}.tar.gz" ]; then
    curl -fSL "$OPENSSL_URL" -o "openssl-${OPENSSL_VER}.tar.gz"
fi

echo "[*] Extraction..."
rm -rf "openssl-${OPENSSL_VER}"
tar xzf "openssl-${OPENSSL_VER}.tar.gz"
cd "openssl-${OPENSSL_VER}"

echo "[*] Configuration pour Windows x64 (mingw-w64)..."
./Configure \
    mingw64 \
    --cross-compile-prefix=x86_64-w64-mingw32- \
    --prefix="$OUT_DIR" \
    --openssldir="$OUT_DIR/ssl" \
    no-shared \
    no-tests \
    no-ui-console \
    -static

echo "[*] Compilation (peut prendre quelques minutes)..."
make -j"$(nproc)" build_libs

echo "[*] Installation des headers et libs..."
mkdir -p "$OUT_DIR/include" "$OUT_DIR/lib"
make install_dev

echo ""
echo "[+] OpenSSL ${OPENSSL_VER} Windows compilé dans :"
echo "    Include : $OUT_DIR/include"
echo "    Libs    : $OUT_DIR/lib"
echo ""
echo "    Vous pouvez maintenant compiler l'implant :"
echo "    make implant C2_IP=192.168.56.104 C2_PORT=4444"
