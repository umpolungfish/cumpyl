/*
 * ca_engine_stub.c
 * A C implementation of the CA engine for the stub.
 * This ports the logic from ca_engine.py to C.
 */

#include <stdint.h>
#include <string.h>

// --- CA Configuration (should match packer) ---
#define CA_GRID_SIZE 256
#define CA_NUM_STEPS 100
#define CA_RULE 30

// --- Internal CA State ---
static uint8_t ca_grid[CA_GRID_SIZE];

// --- Internal Function Prototypes ---
static uint8_t ca_apply_rule_30(uint8_t left, uint8_t center, uint8_t right);

/*
 * Applies Rule 30 to a cell.
 * Rule 30: new_center = left XOR (center OR right)
 */
static uint8_t ca_apply_rule_30(uint8_t left, uint8_t center, uint8_t right) {
    return left ^ (center | right);
}

/*
 * Generates a mask using a 1D Cellular Automaton (Rule 30).
 *
 * Args:
 *   key_material: The key used for seeding (assumed 32 bytes).
 *   block_index: The index of the data block being processed.
 *   mask_length: The desired length of the mask in bytes.
 *   mask_out: Pointer to the output buffer for the mask.
 *
 * Note: This is a direct port of the Python logic. For the stub,
 * a more optimized version might be needed, potentially operating
 * directly on 32/64-bit words instead of bytes.
 */
void ca_generate_mask(const uint8_t *key_material, uint32_t block_index, uint32_t mask_length, uint8_t *mask_out) {
    // 1. Seeding
    // For simplicity, we'll use a basic method to derive the initial state.
    // A more robust hash (like a part of SHA-256) would be better in practice.
    // Here, we'll just XOR the key with the block index and take the first part.
    // This is NOT cryptographically secure but serves as a starting point.
    
    uint8_t seed_buffer[32 + 4]; // Key (32) + Block Index (4)
    memcpy(seed_buffer, key_material, 32);
    // Add block index in little-endian
    seed_buffer[32] = block_index & 0xFF;
    seed_buffer[33] = (block_index >> 8) & 0xFF;
    seed_buffer[34] = (block_index >> 16) & 0xFF;
    seed_buffer[35] = (block_index >> 24) & 0xFF;

    // Simple "hash" for seeding: just use the first CA_GRID_SIZE bits of the seed_buffer.
    // This is highly simplified.
    for (int i = 0; i < CA_GRID_SIZE && i < (32+4)*8; i++) {
        int byte_index = i / 8;
        int bit_index = i % 8;
        ca_grid[i] = (seed_buffer[byte_index] >> bit_index) & 1;
    }
    // Fill the rest of the grid with 0s if seed is smaller
    for (int i = (32+4)*8; i < CA_GRID_SIZE; i++) {
        ca_grid[i] = 0;
    }

    // 2. Evolve CA
    for (uint32_t step = 0; step < CA_NUM_STEPS; step++) {
        uint8_t new_grid[CA_GRID_SIZE];
        for (int i = 0; i < CA_GRID_SIZE; i++) {
            // Handle boundary conditions (fixed, edges are 0)
            uint8_t left = (i > 0) ? ca_grid[i - 1] : 0;
            uint8_t center = ca_grid[i];
            uint8_t right = (i < CA_GRID_SIZE - 1) ? ca_grid[i + 1] : 0;

            new_grid[i] = ca_apply_rule_30(left, center, right);
        }
        // Update grid state
        memcpy(ca_grid, new_grid, CA_GRID_SIZE);
    }

    // 3. Extract Mask
    // Convert the final grid state back to bytes
    // Ensure we don't exceed mask_length
    uint32_t bytes_to_extract = (mask_length < CA_GRID_SIZE / 8) ? mask_length : (CA_GRID_SIZE / 8);
    
    for (uint32_t i = 0; i < bytes_to_extract; i++) {
        uint8_t byte_val = 0;
        // Process 8 bits to form a byte (LSB first within the byte)
        for (int j = 0; j < 8; j++) {
            int grid_index = i * 8 + j;
            if (grid_index < CA_GRID_SIZE && ca_grid[grid_index]) {
                byte_val |= (1 << j);
            }
        }
        mask_out[i] = byte_val;
    }

    // If mask_length is larger than what we can generate, pad with zeros.
    // This shouldn't happen if DEFAULT_BLOCK_SIZE matches CA_GRID_SIZE/8.
    if (mask_length > bytes_to_extract) {
        memset(mask_out + bytes_to_extract, 0, mask_length - bytes_to_extract);
    }
}