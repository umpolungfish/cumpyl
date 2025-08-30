/*
 * Minimal Unpacking Stub for CA-Packer (ELF Implementation)
 * This stub focuses on the core logic: parameter retrieval, CA de-obfuscation, decryption, and jump.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --- Include our custom CA and Crypto engines ---
// We'll include the source files directly for simplicity
#include "ca_engine_stub.c"
#include "chacha20poly1305.c"

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

// --- Simple heap implementation ---
#define HEAP_SIZE 65536 // 64KB heap
static uint8_t heap[HEAP_SIZE];
static size_t heap_offset = 0;

// --- System call numbers for x86-64 Linux ---
#define SYS_MPROTECT 10

/*
 * Simple implementation of malloc for the stub
 */
void *malloc(size_t size) {
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
void free(void *ptr) {
    // In this simple implementation, we don't actually free memory
    // A more sophisticated implementation would handle this
}

/*
 * Simple implementation of exit for the stub
 */
void exit(int status) {
    // In a real implementation, this would exit the program
    // For now, we'll just loop forever
    while(1);
}

/*
 * Simple implementation of memcpy for the stub
 */
void *memcpy(void *dest, const void *src, size_t n) {
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
void *memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;
    
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)c;
    }
    
    return s;
}

/*
 * Simple implementation of mprotect using system call
 */
int mprotect(void *addr, size_t len, int prot) {
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
uintptr_t align_to_page(uintptr_t addr, size_t page_size) {
    return addr & ~(page_size - 1);
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
    uint8_t *decrypted_payload = (uint8_t*)malloc(payload_size);
    if (decrypted_payload == NULL) {
        exit(1);
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
    uint8_t *final_payload = (uint8_t*)malloc(payload_size);
    if (final_payload == NULL) {
        free(decrypted_payload);
        exit(1);
    }
    
    // chacha20_poly1305_decrypt from chacha20poly1305.c
    int decrypt_result = chacha20_poly1305_decrypt_internal(decrypted_payload, payload_size, real_key, nonce, final_payload);
    free(decrypted_payload);
    
    if (decrypt_result != 0) {
        free(final_payload);
        exit(1);
    }
    
    // 6. Make payload memory writable
    // Get page size (typically 4KB on x86-64)
    size_t page_size = 4096;
    
    // Align the payload address to page boundary
    uintptr_t aligned_payload_addr = align_to_page((uintptr_t)payload_address, page_size);
    
    // Calculate the size needed (payload size + offset from page boundary)
    size_t aligned_payload_size = payload_size + ((uintptr_t)payload_address - aligned_payload_addr);
    
    // Make memory writable
    if (mprotect((void*)aligned_payload_addr, aligned_payload_size, PROT_READ | PROT_WRITE) != 0) {
        free(final_payload);
        exit(1);
    }
    
    // 7. Copy the decrypted payload to its original location
    memcpy(payload_address, final_payload, payload_size);
    
    // 8. Make payload memory executable again
    if (mprotect((void*)aligned_payload_addr, aligned_payload_size, PROT_READ | PROT_EXEC) != 0) {
        free(final_payload);
        exit(1);
    }
    
    // 9. Jump to OEP
    // Calculate the absolute address of the OEP
    uint8_t *oep_address = module_base + oep;
    
    // Align the OEP address to page boundary
    uintptr_t aligned_oep_addr = align_to_page((uintptr_t)oep_address, page_size);
    
    // Make OEP memory executable
    if (mprotect((void*)aligned_oep_addr, page_size, PROT_READ | PROT_EXEC) != 0) {
        free(final_payload);
        exit(1);
    }
    
    // Free allocated memory
    free(final_payload);
    
    // Jump to OEP using inline assembly
    __asm__ __volatile__(
        "jmp *%0;"
        :
        : "r" (oep_address)
        : "memory"
    );
    
    // If OEP returns (shouldn't happen)
    exit(0);
}
