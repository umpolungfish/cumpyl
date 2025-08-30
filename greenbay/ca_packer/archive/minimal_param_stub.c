/*
 * Minimal Parameter Reading Stub for CA-Packer
 * This stub combines the working minimal exit stub with parameter reading
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
 * Simple function to convert a byte to hex characters
 */
void byte_to_hex(uint8_t byte, char *hex) {
    const char hex_chars[] = "0123456789ABCDEF";
    hex[0] = hex_chars[(byte >> 4) & 0xF];
    hex[1] = hex_chars[byte & 0xF];
}

/*
 * Stub entry point
 */
void _start() {
    // Message to print
    char msg[] = "Minimal parameter reading stub executed\n";
    int msg_len = 37;
    
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
    
    // Get the base address (using the working approach from minimal functional stub)
    uint8_t *module_base;
    __asm__ __volatile__(
        "lea (%%rip), %0"
        : "=r" (module_base)
        :
        :
    );
    
    // Adjust to approximate base address (this is a hack that worked before)
    module_base = (uint8_t*)((uintptr_t)module_base & ~0xFFF);
    
    // Try to read a parameter
    uint8_t *param_base = module_base + STUB_PARAMETER_OFFSET;
    uint64_t oep = *(uint64_t*)(param_base + OFFSET_OEP);
    
    // Print OEP value in hex
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
    
    // Convert OEP to hex string and print
    char oep_hex[17]; // 16 hex chars + newline
    for (int i = 0; i < 8; i++) {
        byte_to_hex(((uint8_t*)&oep)[7-i], &oep_hex[i*2]);
    }
    oep_hex[16] = '\n';
    
    __asm__ __volatile__(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov $17, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" ((long)STDOUT), "r" (oep_hex), "r" ((long)17)
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