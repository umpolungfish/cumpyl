/*
 * Minimal Functional Stub for CA-Packer
 * This stub just prints a message and exits to verify parameter embedding
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

// --- System call numbers for x86-64 Linux ---
#define SYS_WRITE 1
#define SYS_EXIT 60

// --- File descriptors ---
#define STDOUT 1

/*
 * Stub entry point
 */
void _start() {
    // Message to print
    char msg[] = "Functional stub executed\\n";
    int msg_len = 27;
    
    // Write message to stdout
    __asm__ __volatile__(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" ((long)STDOUT), "r" (msg), "r" ((long)msg_len)
        : "rax", "rdi", "rsi", "rdx"
    );
    
    // Get the base address (this is a simplified approach)
    uint8_t *module_base;
    __asm__ __volatile__(
        "lea (%%rip), %0\n"
        : "=r" (module_base)
        :
        :
    );
    
    // Adjust to approximate base address (this is a hack)
    module_base = (uint8_t*)((uintptr_t)module_base & ~0xFFF);
    
    // Try to read a parameter
    uint8_t *param_base = module_base + STUB_PARAMETER_OFFSET;
    uint64_t oep = *(uint64_t*)(param_base + OFFSET_OEP);
    
    // Print OEP value
    char oep_msg[] = "OEP: 0x";
    __asm__ __volatile__(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov $6, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" ((long)STDOUT), "r" (oep_msg), "r" ((long)6)
        : "rax", "rdi", "rsi", "rdx"
    );
    
    // Exit with code 42
    __asm__ __volatile__(
        "mov $42, %%rdi\n"
        "mov $60, %%rax\n"
        "syscall\n"
        :
        :
        : "rax", "rdi"
    );
    
    // Infinite loop in case syscall fails
    while(1);
}