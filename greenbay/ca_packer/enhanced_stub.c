/*
 * Enhanced Stub for CA-Packer
 * This stub includes improved base address calculation
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
 * Get module base address by finding the ELF header
 * This function walks backwards from the current RIP to find the ELF magic bytes
 */
uint8_t* get_module_base_address() {
    uint8_t *current_addr;
    
    // Get current instruction pointer
    __asm__ __volatile__(
        "lea (%%rip), %0"
        : "=r" (current_addr)
        :
        :
    );
    
    // Align to page boundary
    current_addr = (uint8_t*)((uintptr_t)current_addr & ~0xFFF);
    
    // Walk backwards in 4KB increments to find the ELF header
    // ELF header magic: 0x7f 'E' 'L' 'F'
    while (current_addr > (uint8_t*)0x10000) {
        if (current_addr[0] == 0x7f && 
            current_addr[1] == 'E' && 
            current_addr[2] == 'L' && 
            current_addr[3] == 'F') {
            return current_addr;
        }
        current_addr -= 0x1000;
    }
    
    // Fallback - return approximate base address
    return (uint8_t*)((uintptr_t)current_addr & ~0xFFFFF);
}

/*
 * Stub entry point
 */
void _start() {
    // Message to print
    char msg[] = "Enhanced stub executed\n";
    int msg_len = 24;
    
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
    
    // Get the base address using improved method
    uint8_t *module_base = get_module_base_address();
    
    // Print base address
    char base_msg[] = "Base address: 0x";
    __asm__ __volatile__(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov $16, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" ((long)STDOUT), "r" (base_msg), "r" ((long)16)
        : "rax", "rdi", "rsi", "rdx"
    );
    
    // Print the base address value (simplified)
    // In a real implementation, we'd convert the address to hex string
    
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