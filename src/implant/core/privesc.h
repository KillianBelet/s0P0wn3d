/*
 * privesc.h — UAC Bypass via fodhelper.exe (T1548.002)
 *
 * Bypasses User Account Control by hijacking the auto-elevate
 * mechanism of fodhelper.exe through registry manipulation.
 *
 * MITRE ATT&CK : T1548.002 — Abuse Elevation Control Mechanism: Bypass UAC
 */

#ifndef PRIVESC_H
#define PRIVESC_H

/*
 * privesc_uac_bypass — Lance un exécutable avec élévation via fodhelper.exe.
 *
 * @param exe_path  Chemin de l'exécutable à lancer en admin
 * @return  0 = succès, -1 = erreur registre, -2 = échec lancement fodhelper
 */
int privesc_uac_bypass(const char *exe_path);

#endif /* PRIVESC_H */
