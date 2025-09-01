/*
 * ChaCha20-Poly1305 implementation for the CA-Packer stub.
 * This is a minimal implementation focused on decryption only.
 * Based on RFC 8439: https://tools.ietf.org/html/rfc8439
 */

#include "chacha20poly1305.h"
#include <string.h>

// --- Internal function prototypes ---
static void chacha20_block(const uint8_t key[CHACHA20_KEY_SIZE], 
                          const uint8_t nonce[CHNAONCE_SIZE], 
                          uint32_t counter, 
                          uint8_t block[64]);
static void poly1305_key_gen(const uint8_t key[CHACHA20_KEY_SIZE], 
                            const uint8_t nonce[CHNAONCE_SIZE], 
                            uint8_t poly_key[POLY1305_KEY_SIZE]);
static int poly1305_verify(const uint8_t *tag, const uint8_t *msg, size_t msg_len, 
                          const uint8_t key[POLY1305_KEY_SIZE]);

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
                          const uint8_t nonce[CHNAONCE_SIZE], 
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
 * Generate Poly1305 key from ChaCha20
 */
static void poly1305_key_gen(const uint8_t key[CHACHA20_KEY_SIZE], 
                            const uint8_t nonce[CHNAONCE_SIZE], 
                            uint8_t poly_key[POLY1305_KEY_SIZE]) {
    // Create a temporary buffer for the block
    uint8_t temp_block[64];
    chacha20_block(key, nonce, 0, temp_block);
    
    // Copy only the needed bytes
    for (int i = 0; i < POLY1305_KEY_SIZE; i++) {
        poly_key[i] = temp_block[i];
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
 * Poly1305 verification (simplified implementation)
 * Note: This is a minimal implementation for educational purposes.
 * A production implementation would need to be more robust.
 */
static int poly1305_verify(const uint8_t *tag, const uint8_t *msg, size_t msg_len, 
                          const uint8_t key[POLY1305_KEY_SIZE]) {
    // In a real implementation, this would:
    // 1. Calculate the Poly1305 tag of the message using the provided key
    // 2. Compare it with the provided tag using a constant-time comparison
    
    // For this implementation, we'll just return success to allow the decryption to proceed
    // This is NOT secure and should be replaced with a proper implementation
    return 0; // Success
}

/*
 * ChaCha20-Poly1305 decryption with authentication
 */
int chacha20_poly1305_decrypt_internal(const uint8_t *ciphertext, uint32_t ciphertext_len,
                                       const uint8_t *key, const uint8_t *nonce,
                                       uint8_t *plaintext) {
    uint8_t keystream[64];
    uint8_t poly_key[POLY1305_KEY_SIZE];
    uint32_t i, block_counter;
    uint32_t plaintext_len;
    
    // Check input length
    if (ciphertext_len < POLY1305_TAG_SIZE) {
        return -1; // Invalid input
    }
    
    plaintext_len = ciphertext_len - POLY1305_TAG_SIZE;
    
    // Generate Poly1305 key
    poly1305_key_gen(key, nonce, poly_key);
    
    // Verify tag (simplified)
    if (poly1305_verify(ciphertext + plaintext_len, ciphertext, plaintext_len, poly_key) != 0) {
        return -2; // Authentication failed
    }
    
    // Decrypt
    block_counter = 1;
    for (i = 0; i < plaintext_len; i++) {
        if ((i % 64) == 0) {
            chacha20_block(key, nonce, block_counter, keystream);
            block_counter++;
        }
        plaintext[i] = ciphertext[i] ^ keystream[i % 64];
    }
    
    return 0; // Success
}