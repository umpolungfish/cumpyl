/*
 * crypto_engine_stub.c
 * Stub implementation of ChaCha20-Poly1305 decryption for the CA-Packer.
 */

#include <stdint.h>
#include <string.h>

// --- Constants ---
#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12
#define POLY1305_TAG_SIZE 16

// --- Internal function prototypes ---
static void chacha20_block(const uint8_t key[CHACHA20_KEY_SIZE], 
                          const uint8_t nonce[CHACHA20_NONCE_SIZE], 
                          uint32_t counter, 
                          uint8_t block[64]);

// --- ChaCha20 quarter round ---
#define QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] ^= x[a]; x[d] = (x[d] << 16) | (x[d] >> 16); \
    x[c] += x[d]; x[b] ^= x[c]; x[b] = (x[b] << 12) | (x[b] >> 20); \
    x[a] += x[b]; x[d] ^= x[a]; x[d] = (x[d] << 8) | (x[d] >> 24); \
    x[c] += x[d]; x[b] ^= x[c]; x[b] = (x[b] << 7) | (x[b] >> 25);

/*
 * ChaCha20 block function
 */
static void chacha20_block(const uint8_t key[CHACHA20_KEY_SIZE], 
                          const uint8_t nonce[CHACHA20_NONCE_SIZE], 
                          uint32_t counter, 
                          uint8_t block[64]) {
    uint32_t state[16];
    uint32_t working[16];
    int i;

    // Constants "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key
    for (i = 0; i < 8; i++) {
        state[4 + i] = (key[4 * i] | (key[4 * i + 1] << 8) | 
                       (key[4 * i + 2] << 16) | (key[4 * i + 3] << 24));
    }

    // Counter
    state[12] = counter;

    // Nonce
    for (i = 0; i < 3; i++) {
        state[13 + i] = (nonce[4 * i] | (nonce[4 * i + 1] << 8) | 
                        (nonce[4 * i + 2] << 16) | (nonce[4 * i + 3] << 24));
    }

    // Copy state to working
    for (i = 0; i < 16; i++) {
        working[i] = state[i];
    }

    // 20 rounds (10 column-dia rounds)
    for (i = 0; i < 10; i++) {
        // Column rounds
        QUARTERROUND(working, 0, 4, 8, 12);
        QUARTERROUND(working, 1, 5, 9, 13);
        QUARTERROUND(working, 2, 6, 10, 14);
        QUARTERROUND(working, 3, 7, 11, 15);
        // Diagonal rounds
        QUARTERROUND(working, 0, 5, 10, 15);
        QUARTERROUND(working, 1, 6, 11, 12);
        QUARTERROUND(working, 2, 7, 8, 13);
        QUARTERROUND(working, 3, 4, 9, 14);
    }

    // Add initial state
    for (i = 0; i < 16; i++) {
        working[i] += state[i];
    }

    // Serialize
    for (i = 0; i < 16; i++) {
        block[4 * i] = working[i] & 0xff;
        block[4 * i + 1] = (working[i] >> 8) & 0xff;
        block[4 * i + 2] = (working[i] >> 16) & 0xff;
        block[4 * i + 3] = (working[i] >> 24) & 0xff;
    }
}

/*
 * Simple constant-time comparison
 */
static int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t result = 0;
    size_t i;
    
    for (i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    
    return result;
}

/*
 * crypto_engine_stub.c
 * A wrapper for the ChaCha20-Poly1305 decryption logic.
 */

#include "chacha20poly1305.h"
#include <stdint.h>

/*
 * Decrypts data using ChaCha20-Poly1305.
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
int chacha20_poly1305_decrypt(const uint8_t *ciphertext, uint32_t ciphertext_len,
                              const uint8_t *key, const uint8_t *nonce,
                              uint8_t *plaintext) {
    // Delegate to our implementation
    return chacha20_poly1305_decrypt_internal(ciphertext, ciphertext_len, key, nonce, plaintext);
}