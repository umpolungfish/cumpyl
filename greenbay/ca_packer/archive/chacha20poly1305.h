/*
 * chacha20poly1305.h
 * Header file for ChaCha20-Poly1305 implementation.
 */

#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <stdint.h>

// --- Constants ---
#define CHACHA20_KEY_SIZE 32
#define CHNAONCE_SIZE 12
#define POLY1305_KEY_SIZE 32
#define POLY1305_TAG_SIZE 16

/*
 * ChaCha20-Poly1305 decryption with authentication
 *
 * Args:
 *   ciphertext: The encrypted data (including the authentication tag).
 *   ciphertext_len: Length of the ciphertext.
 *   key: The 32-byte decryption key.
 *   nonce: The 12-byte nonce.
 *   plaintext: Output buffer for the decrypted data.
 *
 * Returns:
 *   0 on success, non-zero on failure (e.g., authentication failure).
 */
int chacha20_poly1305_decrypt_internal(const uint8_t *ciphertext, uint32_t ciphertext_len,
                                       const uint8_t *key, const uint8_t *nonce,
                                       uint8_t *plaintext);

#endif // CHACHA20POLY1305_H