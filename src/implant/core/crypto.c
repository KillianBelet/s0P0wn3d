/*
 * crypto.c — Implémentation de la couche de chiffrement réseau
 */

/* winsock2.h doit précéder windows.h */
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>

#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "crypto.h"

/* ================================================================
 * Clé de session AES-256
 *
 * Privée à ce fichier (static) : seul rsa_handshake() la remplit,
 * seuls send_enc() et recv_dec() la lisent.
 * ================================================================ */

static uint8_t SESSION_KEY[32];

/* ================================================================
 * Helpers réseau
 * ================================================================ */

int recv_all(SOCKET sock, uint8_t *buf, int n)
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

/* ================================================================
 * Envoi chiffré
 * ================================================================ */

int send_enc(SOCKET sock, const uint8_t *data, int data_len)
{
    int     pad        = AES_BLOCKLEN - (data_len % AES_BLOCKLEN);
    int     padded_len = data_len + pad;
    uint8_t *buf       = (uint8_t *)malloc(padded_len);

    if (!buf)
        return -1;

    memcpy(buf, data, data_len);
    memset(buf + data_len, pad, pad);

    /* IV aléatoire via le CSPRNG système */
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

/* ================================================================
 * Réception déchiffrée
 * ================================================================ */

uint8_t *recv_dec(SOCKET sock, int *out_len)
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
 * ================================================================ */

int rsa_handshake(SOCKET sock)
{
    /* Étape 1 : recevoir la clé publique RSA (BCRYPT_RSAPUBLIC_BLOB) */
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

    /* Étape 2 : générer la SESSION_KEY AES-256 aléatoire */
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

    st = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB,
                             &hKey, blob, (ULONG)blob_len, 0);
    free(blob);

    if (!BCRYPT_SUCCESS(st)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    /* RSA-OAEP-SHA256 — identique côté Python :
     * padding.OAEP(mgf=MGF1(SHA256()), algorithm=SHA256()) */
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
    send(sock, (char *)len_hdr, 4,       0);
    send(sock, (char *)enc,     enc_len, 0);

    free(enc);
    return 0;
}
