/*
 * Base Address Test Stub for CA-Packer
 * This stub tests that we can get the base address correctly
 */

#include <stdint.h>

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
    
    // Instead of trying to read parameters, let's just exit with a code
    // that tells us what the base address was
    // We'll use the lower 8 bits of the base address as the exit code
    // This will help us verify that we're getting a reasonable base address
    
    // Exit with code based on base address
    __asm__ __volatile__(
        "mov %0, %%rdi\n"
        "and $0xFF, %%edi\n"  // Only use lower 8 bits
        "mov $60, %%rax\n"
        "syscall\n"
        :
        : "r" (module_base)
        : "rax", "rdi", "memory"
    );
    
    // Infinite loop in case syscall fails
    while(1);
}
