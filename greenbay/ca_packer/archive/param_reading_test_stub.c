/*
 * Parameter Reading Test Stub for CA-Packer
 * This stub attempts to read embedded parameters in a safe way
 */

#include <stdint.h>

// --- Configuration ---
#define STUB_PARAMETER_OFFSET 0x400

// --- Parameter Offsets ---
#define OFFSET_OEP            0x00  // 8 bytes
#define OFFSET_PAYLOAD_SIZE   0x3C  // 4 bytes

// --- System call numbers for x86-64 Linux ---
#define SYS_EXIT 60

/*
 * Get module base address using call/pop technique
 */
uint8_t* get_module_base() {
    uint8_t *rip;
    // Use call/pop to get current instruction pointer
    __asm__ __volatile__(
        "call 1f\n"
        "1: pop %0\n"
        : "=r" (rip)
        :
        :
    );
    
    // Align to page boundary
    return (uint8_t*)((uintptr_t)rip & ~0xFFF);
}

/*
 * Stub entry point
 */
void _start() {
    // Get the base address using call/pop technique
    uint8_t *module_base = get_module_base();
    
    // Calculate parameter base address
    uint8_t *param_base = module_base + STUB_PARAMETER_OFFSET;
    
    // Try to read parameters safely
    // We'll use a simple approach: read the values and store them in local variables
    // This avoids complex memory operations that might cause issues
    uint64_t oep = 0;
    uint32_t payload_size = 0;
    
    // Copy the values byte by byte to avoid alignment issues
    for (int i = 0; i < 8; i++) {
        ((uint8_t*)&oep)[i] = param_base[OFFSET_OEP + i];
    }
    
    for (int i = 0; i < 4; i++) {
        ((uint8_t*)&payload_size)[i] = param_base[OFFSET_PAYLOAD_SIZE + i];
    }
    
    // Exit with code 42
    __asm__ __volatile__(
        "mov $42, %%rdi\n"
        "mov $60, %%rax\n"
        "syscall\n"
        :
        :
        : "rax", "rdi", "memory"
    );
    
    // Infinite loop in case syscall fails
    while(1);
}