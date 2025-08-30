/*
 * Parameter Reading Stub for CA-Packer
 * This stub focuses on reading embedded parameters correctly
 * while avoiding segmentation faults
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

// Fixed obfuscation key used for key de-obfuscation
#define FIXED_OBFUS_KEY 0xCABEFEBEEFBEADDE

/*
 * Simple function to convert a byte to hex characters
 */
void byte_to_hex(uint8_t byte, char *hex) {
    const char hex_chars[] = "0123456789ABCDEF";
    hex[0] = hex_chars[(byte >> 4) & 0xF];
    hex[1] = hex_chars[byte & 0xF];
}

/*
 * Convert a 64-bit value to a hex string
 */
void u64_to_hex(uint64_t value, char *hex) {
    for (int i = 0; i < 8; i++) {
        byte_to_hex(((uint8_t*)&value)[7-i], &hex[i*2]);
    }
}

/*
 * Convert a 32-bit value to a decimal string
 */
int u32_to_decimal(uint32_t value, char *str) {
    if (value == 0) {
        str[0] = '0';
        str[1] = '\n';
        return 2;
    }
    
    int len = 0;
    uint32_t temp = value;
    
    // Convert to string (reverse order)
    while (temp > 0) {
        str[len++] = (temp % 10) + '0';
        temp /= 10;
    }
    
    // Reverse the string
    for (int i = 0; i < len/2; i++) {
        char tmp = str[i];
        str[i] = str[len-1-i];
        str[len-1-i] = tmp;
    }
    
    str[len] = '\n';
    return len + 1;
}

/*
 * De-obfuscate a 64-bit key part
 */
uint64_t deobfuscate_key_part(uint64_t obfuscated_part) {
    return obfuscated_part ^ FIXED_OBFUS_KEY;
}

/*
 * Stub entry point
 */
void _start() {
    // Message to print
    char msg[] = "Parameter reading stub executed\n";
    __asm__ __volatile__(
        "mov $1, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov $30, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" (msg)
        : "rax", "rdi", "rsi", "rdx"
    );
    
    // Get the base address (using the working approach)
    uint8_t *module_base;
    __asm__ __volatile__(
        "lea (%%rip), %0"
        : "=r" (module_base)
        :
        :
    );
    
    // Adjust to approximate base address (this worked before)
    module_base = (uint8_t*)((uintptr_t)module_base & ~0xFFF);
    
    // Calculate parameter base address
    uint8_t *param_base = module_base + STUB_PARAMETER_OFFSET;
    
    // Try to read parameters
    uint64_t oep = *(uint64_t*)(param_base + OFFSET_OEP);
    
    // Print OEP value in hex
    char oep_msg[] = "OEP: 0x";
    __asm__ __volatile__(
        "mov $1, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov $6, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" (oep_msg)
        : "rax", "rdi", "rsi", "rdx"
    );
    
    // Convert OEP to hex string and print
    char oep_hex[17]; // 16 hex chars + newline
    u64_to_hex(oep, oep_hex);
    oep_hex[16] = '\n';
    
    __asm__ __volatile__(
        "mov $1, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov $17, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" (oep_hex)
        : "rax", "rdi", "rsi", "rdx"
    );
    
    // Also try to read payload size
    uint32_t payload_size = *(uint32_t*)(param_base + OFFSET_PAYLOAD_SIZE);
    
    char size_msg[] = "Payload size: ";
    __asm__ __volatile__(
        "mov $1, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov $14, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" (size_msg)
        : "rax", "rdi", "rsi", "rdx"
    );
    
    // Convert payload size to decimal string and print
    char size_str[12]; // Enough for 32-bit number
    int len = u32_to_decimal(payload_size, size_str);
    
    __asm__ __volatile__(
        "mov $1, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov %1, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" (size_str), "r" ((long)len)
        : "rax", "rdi", "rsi", "rdx"
    );
    
    // Try to read and de-obfuscate a key part
    uint64_t obfuscated_key_part = *(uint64_t*)(param_base + OFFSET_KEY_OBFUS);
    uint64_t deobfuscated_key_part = deobfuscate_key_part(obfuscated_key_part);
    
    char key_msg[] = "Key part: 0x";
    __asm__ __volatile__(
        "mov $1, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov $11, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" (key_msg)
        : "rax", "rdi", "rsi", "rdx"
    );
    
    // Convert key part to hex string and print
    char key_hex[17]; // 16 hex chars + newline
    u64_to_hex(deobfuscated_key_part, key_hex);
    key_hex[16] = '\n';
    
    __asm__ __volatile__(
        "mov $1, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov $17, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" (key_hex)
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
