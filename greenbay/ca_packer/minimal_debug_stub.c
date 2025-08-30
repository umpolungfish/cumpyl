/*
 * Minimal Debug Stub for CA-Packer
 * This stub focuses on debugging the core functionality:
 * 1. Finding the base address
 * 2. Reading parameters from fixed offsets
 * 3. Locating the payload section
 * 4. Exiting gracefully
 */

#include <stdint.h>

// --- Configuration ---
#define STUB_PARAMETER_OFFSET 0x400

// --- Parameter Offsets ---
#define OFFSET_OEP            0x00  // 8 bytes
#define OFFSET_KEY_OBFUS      0x08  // 32 bytes (Obfuscated)
#define OFFSET_NONCE          0x28  // 12 bytes
#define OFFSET_CA_STEPS       0x34  // 4 bytes
#define OFFSET_PAYLOAD_RVA    0x38  // 4 bytes
#define OFFSET_PAYLOAD_SIZE   0x3C  // 4 bytes

// --- ELF Header Magic ---
#define ELF_MAGIC 0x464C457F

// --- System call numbers for x86-64 Linux ---
#define SYS_EXIT 60

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
 * Simple implementation of exit using system call
 */
void exit(int status) {
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
 * Stub entry point
 */
void _start() {
    // Try to get the base address
    uint8_t *module_base = get_module_base();
    
    // Try to read a parameter
    uint8_t *param_base = module_base + STUB_PARAMETER_OFFSET;
    
    // Try to read the OEP (this might cause a segfault if addresses are wrong)
    uint64_t oep = *(uint64_t*)(param_base + OFFSET_OEP);
    
    // Exit with a code that indicates we got here
    // Use part of the OEP as the exit code to verify we read something
    exit((int)(oep & 0xFF));
}