/*
 * crypto.h — Couche de chiffrement réseau
 *
 * Gère :
 *   - La SESSION_KEY AES-256 (privée, générée par rsa_handshake)
 *   - Le handshake RSA-2048 (échange de clé asymétrique)
 *   - L'envoi / réception de frames chiffrés AES-256-CBC
 *
 * Format d'un frame :
 *   [4B big-endian : total_len = 16 + len(ciphertext)]
 *   [16B           : IV aléatoire (BCryptGenRandom)]
 *   [?B            : AES-256-CBC ciphertext (PKCS#7)]
 *
 * MITRE ATT&CK : T1573.002 — Asymmetric Cryptography
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <winsock2.h>

/*
 * Lit exactement n octets depuis la socket (lecture bloquante).
 * Retourne -1 si la connexion est fermée avant la fin.
 */
int recv_all(SOCKET sock, uint8_t *buf, int n);

/*
 * Chiffre data (data_len octets) avec AES-256-CBC / SESSION_KEY
 * et envoie le frame sur sock.
 * Retourne 0 si succès, -1 si erreur.
 */
int send_enc(SOCKET sock, const uint8_t *data, int data_len);

/*
 * Reçoit un frame chiffré, le déchiffre et retourne les données claires.
 * *out_len est rempli avec la taille du résultat.
 * Le buffer retourné est alloué avec malloc — à libérer avec free().
 * Retourne NULL si erreur.
 */
uint8_t *recv_dec(SOCKET sock, int *out_len);

/*
 * Effectue le handshake RSA-2048 :
 *   1. Reçoit la clé publique RSA du serveur (BCRYPT_RSAPUBLIC_BLOB)
 *   2. Génère SESSION_KEY (32B aléatoires via BCryptGenRandom)
 *   3. Chiffre SESSION_KEY avec RSA-OAEP-SHA256
 *   4. Envoie la SESSION_KEY chiffrée au serveur
 *
 * Retourne 0 si succès, -1 si erreur.
 */
int rsa_handshake(SOCKET sock);

#endif /* CRYPTO_H */
