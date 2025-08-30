/*
 * Parameter Reading Stub for CA-Packer
 * This stub focuses on reading embedded parameters correctly
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
    char msg[] = "Parameter reading stub executed\n";
    int msg_len = 30;
    
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
    
    // Get the base address (simple approach for now)
    uint8_t *module_base;
    __asm__ __volatile__(
        "lea (%%rip), %0"
        : "=r" (module_base)
        :
        :
    );
    
    // Align to page boundary (simplified approach)
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
    char oep_hex[17]; // 16 hex chars + null terminator
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
    
    // Also try to read payload size
    uint32_t payload_size = *(uint32_t*)(param_base + OFFSET_PAYLOAD_SIZE);
    
    char size_msg[] = "Payload size: ";
    __asm__ __volatile__(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov $14, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" ((long)STDOUT), "r" (size_msg), "r" ((long)14)
        : "rax", "rdi", "rsi", "rdx"
    );
    
    // Convert payload size to decimal string and print
    char size_str[12]; // Enough for 32-bit number
    int len = 0;
    uint32_t temp = payload_size;
    
    // Handle zero case
    if (temp == 0) {
        size_str[0] = '0';
        len = 1;
    } else {
        // Convert to string (reverse order)
        while (temp > 0) {
            size_str[len++] = (temp % 10) + '0';
            temp /= 10;
        }
        
        // Reverse the string
        for (int i = 0; i < len/2; i++) {
            char tmp = size_str[i];
            size_str[i] = size_str[len-1-i];
            size_str[len-1-i] = tmp;
        }
    }
    
    size_str[len] = '\n';
    
    __asm__ __volatile__(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" ((long)STDOUT), "r" (size_str), "r" ((long)(len+1))
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