/*
 * privesc.h — Privilege escalation via PrintNightmare LPE
 *
 * Exploits CVE-2021-1675 / CVE-2021-34527 to load a DLL
 * as SYSTEM through the Windows Print Spooler service.
 *
 * MITRE ATT&CK : T1068 — Exploitation for Privilege Escalation
 */

#ifndef PRIVESC_H
#define PRIVESC_H

/*
 * Exploit PrintNightmare LPE to load dll_path as SYSTEM.
 *
 * The DLL is copied into the Spooler driver directory and loaded
 * by the Print Spooler service (running as SYSTEM).
 *
 * dll_path must point to an existing DLL on the target filesystem.
 *
 * Returns 0 on success, negative on error:
 *   -1  DLL not found
 *   -2  could not locate a valid print driver (UNIDRV.DLL)
 *   -3  AddPrinterDriverExA failed (Spooler patched or stopped)
 */
int privesc_printnightmare(const char *dll_path);

#endif /* PRIVESC_H */
