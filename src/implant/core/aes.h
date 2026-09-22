/*
 * aes.h — AES-256-CBC (tiny-AES-c embarqué, sans dépendance externe)
 *
 * Interface publique : trois fonctions.
 * Tout le reste (tables, primitives GF) est privé dans aes.c.
 *
 * Référence : NIST FIPS 197
 */

#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCKLEN    16   /* taille d'un bloc AES en octets       */
#define AES_KEYLEN      32   /* AES-256 : clé de 256 bits = 32 octets */
#define AES_keyExpSize 240   /* taille du tableau de sous-clés        */

typedef struct {
    uint8_t RoundKey[AES_keyExpSize];
    uint8_t Iv[AES_BLOCKLEN];
} AES_ctx;

/*
 * Initialise le contexte AES avec une clé (32 octets) et un IV (16 octets).
 * À appeler avant chaque encrypt/decrypt.
 */
void AES_init_ctx_iv(AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);

/* Chiffre buf en place (longueur multiple de AES_BLOCKLEN). */
void AES_CBC_encrypt(AES_ctx *ctx, uint8_t *buf, size_t len);

/* Déchiffre buf en place (longueur multiple de AES_BLOCKLEN). */
void AES_CBC_decrypt(AES_ctx *ctx, uint8_t *buf, size_t len);

#endif /* AES_H */
