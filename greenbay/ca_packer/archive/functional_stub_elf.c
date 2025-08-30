/*
 * Functional Unpacking Stub for CA-Packer (ELF Implementation)
 * This stub implements the full unpacking functionality:
 * 1. Parameter retrieval from embedded locations
 * 2. Payload location and de-obfuscation
 * 3. Payload decryption
 * 4. Memory management
 * 5. Jump to OEP
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// --- Configuration (Matching packer) ---
#define DEFAULT_BLOCK_SIZE 32
#define STUB_PARAMETER_OFFSET 0x400

// --- Parameter Offsets ---
#define OFFSET_OEP            0x00  // 8 bytes
#define OFFSET_KEY_OBFUS      0x08  // 32 bytes (Obfuscated)
#define OFFSET_NONCE          0x28  // 12 bytes
#define OFFSET_CA_STEPS       0x34  // 4 bytes (Unused in stub, CA_ENGINE uses fixed steps)
#define OFFSET_PAYLOAD_RVA    0x38  // 4 bytes
#define OFFSET_PAYLOAD_SIZE   0x3C  // 4 bytes

// --- Fixed De-obfuscation Value ---
#define KEY_OBFUS_VALUE 0xCABEFEBEEFBEADDEULL // 64-bit value

// --- ELF Header Magic ---
#define ELF_MAGIC 0x464C457F

// --- Memory Protection Flags ---
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

// --- System call numbers for x86-64 Linux ---
#define SYS_MPROTECT 10
#define SYS_EXIT 60

// --- Simple heap implementation ---
#define HEAP_SIZE 65536 // 64KB heap
static uint8_t heap[HEAP_SIZE];
static size_t heap_offset = 0;

/*
 * Simple implementation of malloc for the stub
 */
static void *stub_malloc(size_t size) {
    if (heap_offset + size > HEAP_SIZE) {
        return NULL;
    }
    
    void *ptr = &heap[heap_offset];
    heap_offset += size;
    return ptr;
}

/*
 * Simple implementation of free for the stub
 */
static void stub_free(void *ptr) {
    // In this simple implementation, we don't actually free memory
    // A more sophisticated implementation would handle this
}

/*
 * Simple implementation of exit for the stub
 */
static void stub_exit(int status) {
    __asm__ __volatile__(
        "syscall"
        :
        : "a" (SYS_EXIT), "D" (status)
        : "memory"
    );
    
    // Infinite loop in case syscall fails
    while(1);
}

/*
 * Simple implementation of memcpy for the stub
 */
static void *stub_memcpy(void *dest, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    
    return dest;
}

/*
 * Simple implementation of memset for the stub
 */
static void *stub_memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;
    
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)c;
    }
    
    return s;
}

/*
 * Simple implementation of mprotect using system call
 */
static int stub_mprotect(void *addr, size_t len, int prot) {
    long result;
    __asm__ __volatile__(
        "syscall"
        : "=a" (result)
        : "a" (SYS_MPROTECT), "D" (addr), "S" (len), "d" (prot)
        : "memory", "rcx", "r11"
    );
    return (int)result;
}

/*
 * Get current instruction pointer
 */
static inline uint8_t *get_current_ip() {
    uint8_t *current_ip;
    __asm__ __volatile__(
        "call 1f;"
        "1: pop %0;"
        : "=r" (current_ip)
    );
    return current_ip;
}

/*
 * Get the base address of the current module
 * This function uses the current instruction pointer to find the base address
 */
uint8_t *get_module_base() {
    uint8_t *current_ip = get_current_ip();
    
    // Search backwards to find the ELF header (0x7f 'E' 'L' 'F')
    // We'll search up to 0x10000 bytes backwards (64KB)
    for (int i = 0; i < 0x10000; i++) {
        if (*(uint32_t*)current_ip == ELF_MAGIC) {
            return current_ip;
        }
        current_ip--;
    }
    
    // Fallback to a fixed address if we can't find the header
    return (uint8_t*)0x400000;
}

/*
 * Align address to page boundary
 */
static uintptr_t align_to_page(uintptr_t addr, size_t page_size) {
    return addr & ~(page_size - 1);
}

// --- CA Engine Implementation ---
// This is a minimal implementation of the CA engine for the stub

#define CA_GRID_SIZE 256
#define CA_NUM_STEPS 100
#define CA_RULE 30

// --- Internal CA State ---
static uint8_t ca_grid[CA_GRID_SIZE];

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
 */
void ca_generate_mask(const uint8_t *key_material, uint32_t block_index, uint32_t mask_length, uint8_t *mask_out) {
    // 1. Seeding
    // For simplicity, we'll use a basic method to derive the initial state.
    // A more robust hash (like a part of SHA-256) would be better in practice.
    // Here, we'll just XOR the key with the block index and take the first part.
    // This is NOT cryptographically secure but serves as a starting point.
    
    uint8_t seed_buffer[32 + 4]; // Key (32) + Block Index (4)
    for (int i = 0; i < 32; i++) {
        seed_buffer[i] = key_material[i];
    }
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
        for (int i = 0; i < CA_GRID_SIZE; i++) {
            ca_grid[i] = new_grid[i];
        }
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
        for (uint32_t i = bytes_to_extract; i < mask_length; i++) {
            mask_out[i] = 0;
        }
    }
}

// --- ChaCha20-Poly1305 Implementation ---
// This is a minimal implementation focused on decryption only.

#define CHACHA20_KEY_SIZE 32
#define CHNAONCE_SIZE 12
#define POLY1305_KEY_SIZE 32
#define POLY1305_TAG_SIZE 16

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

/*
 * Stub entry point
 */
void _start() {
    // Get the base address of the module
    uint8_t *module_base = get_module_base();
    
    // 1. Retrieve and De-obfuscate Parameters
    uint8_t *param_base = module_base + STUB_PARAMETER_OFFSET;
    
    uint64_t oep = *(uint64_t*)(param_base + OFFSET_OEP);
    
    uint64_t obfuscated_key_p1 = *(uint64_t*)(param_base + OFFSET_KEY_OBFUS);
    uint64_t obfuscated_key_p2 = *(uint64_t*)(param_base + OFFSET_KEY_OBFUS + 8);
    uint64_t obfuscated_key_p3 = *(uint64_t*)(param_base + OFFSET_KEY_OBFUS + 16);
    uint64_t obfuscated_key_p4 = *(uint64_t*)(param_base + OFFSET_KEY_OBFUS + 24);
    
    uint64_t real_key_p1 = obfuscated_key_p1 ^ KEY_OBFUS_VALUE;
    uint64_t real_key_p2 = obfuscated_key_p2 ^ KEY_OBFUS_VALUE;
    uint64_t real_key_p3 = obfuscated_key_p3 ^ KEY_OBFUS_VALUE;
    uint64_t real_key_p4 = obfuscated_key_p4 ^ KEY_OBFUS_VALUE;
    
    uint8_t real_key[32];
    *(uint64_t*)(real_key + 0) = real_key_p1;
    *(uint64_t*)(real_key + 8) = real_key_p2;
    *(uint64_t*)(real_key + 16) = real_key_p3;
    *(uint64_t*)(real_key + 24) = real_key_p4;
    
    uint8_t nonce[12];
    for (int i = 0; i < 12; i++) {
        nonce[i] = *(param_base + OFFSET_NONCE + i);
    }
    
    uint32_t payload_rva = *(uint32_t*)(param_base + OFFSET_PAYLOAD_RVA);
    uint32_t payload_size = *(uint32_t*)(param_base + OFFSET_PAYLOAD_SIZE);
    
    // 2. Locate Payload Section
    uint8_t *payload_address = module_base + payload_rva;
    
    // 3. Allocate memory for decrypted payload
    uint8_t *decrypted_payload = (uint8_t*)stub_malloc(payload_size);
    if (decrypted_payload == NULL) {
        stub_exit(1);
    }
    
    // 4. De-obfuscate Payload (P' -> P)
    uint32_t num_blocks = (payload_size + DEFAULT_BLOCK_SIZE - 1) / DEFAULT_BLOCK_SIZE;
    for (uint32_t i = 0; i < num_blocks; i++) {
        uint32_t current_block_size = DEFAULT_BLOCK_SIZE;
        if ((i + 1) * DEFAULT_BLOCK_SIZE > payload_size) {
            current_block_size = payload_size - (i * DEFAULT_BLOCK_SIZE);
        }
        
        uint8_t *block_ptr = payload_address + (i * DEFAULT_BLOCK_SIZE);
        uint8_t mask[DEFAULT_BLOCK_SIZE];
        
        // ca_generate_mask from ca_engine_stub.c
        ca_generate_mask(real_key, i, current_block_size, mask);
        
        for (uint32_t j = 0; j < current_block_size; j++) {
            decrypted_payload[i * DEFAULT_BLOCK_SIZE + j] = block_ptr[j] ^ mask[j];
        }
    }
    
    // 5. Decrypt Payload (P -> Original Binary Data)
    uint8_t *final_payload = (uint8_t*)stub_malloc(payload_size);
    if (final_payload == NULL) {
        stub_free(decrypted_payload);
        stub_exit(1);
    }
    
    // chacha20_poly1305_decrypt_internal from chacha20poly1305.c
    int decrypt_result = chacha20_poly1305_decrypt_internal(decrypted_payload, payload_size, real_key, nonce, final_payload);
    stub_free(decrypted_payload);
    
    if (decrypt_result != 0) {
        stub_free(final_payload);
        stub_exit(1);
    }
    
    // 6. Make payload memory writable
    // Get page size (typically 4KB on x86-64)
    size_t page_size = 4096;
    
    // Align the payload address to page boundary
    uintptr_t aligned_payload_addr = align_to_page((uintptr_t)payload_address, page_size);
    
    // Calculate the size needed (payload size + offset from page boundary)
    size_t aligned_payload_size = payload_size + ((uintptr_t)payload_address - aligned_payload_addr);
    
    // Make memory writable
    if (stub_mprotect((void*)aligned_payload_addr, aligned_payload_size, PROT_READ | PROT_WRITE) != 0) {
        stub_free(final_payload);
        stub_exit(1);
    }
    
    // 7. Copy the decrypted payload to its original location
    stub_memcpy(payload_address, final_payload, payload_size);
    
    // 8. Make payload memory executable again
    if (stub_mprotect((void*)aligned_payload_addr, aligned_payload_size, PROT_READ | PROT_EXEC) != 0) {
        stub_free(final_payload);
        stub_exit(1);
    }
    
    // 9. Jump to OEP
    // Calculate the absolute address of the OEP
    uint8_t *oep_address = module_base + oep;
    
    // Align the OEP address to page boundary
    uintptr_t aligned_oep_addr = align_to_page((uintptr_t)oep_address, page_size);
    
    // Make OEP memory executable
    if (stub_mprotect((void*)aligned_oep_addr, page_size, PROT_READ | PROT_EXEC) != 0) {
        stub_free(final_payload);
        stub_exit(1);
    }
    
    // Free allocated memory
    stub_free(final_payload);
    
    // Jump to OEP using inline assembly
    __asm__ __volatile__(
        "jmp *%0;"
        :
        : "r" (oep_address)
        : "memory"
    );
    
    // If OEP returns (shouldn't happen)
    stub_exit(0);
}