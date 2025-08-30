/*
 * Simple Parameter Reading Stub for CA-Packer
 * This stub focuses on reading embedded parameters with minimal complexity
 */

#include <stdint.h>

// --- Configuration ---
#define STUB_PARAMETER_OFFSET 0x400

// --- Parameter Offsets ---
#define OFFSET_OEP            0x00  // 8 bytes
#define OFFSET_PAYLOAD_SIZE   0x3C  // 4 bytes

// --- System call numbers for x86-64 Linux ---
#define SYS_EXIT 60

// Add some code to make sure this stub is larger than 50 bytes
// This will ensure the packer embeds parameters

/*
 * Simple function that does nothing but adds to the code size
 */
void dummy_function() {
    volatile int a = 1;
    volatile int b = 2;
    volatile int c = 3;
    volatile int d = 4;
    volatile int e = 5;
    volatile int f = 6;
    volatile int g = 7;
    volatile int h = 8;
    volatile int i = 9;
    volatile int j = 10;
    
    // Do some dummy operations to prevent optimization
    volatile int result = a + b + c + d + e + f + g + h + i + j;
    (void)result; // Prevent unused variable warning
}

/*
 * Stub entry point
 */
void _start() {
    // Call the dummy function to make sure it's included
    dummy_function();
    
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
    uint32_t payload_size = *(uint32_t*)(param_base + OFFSET_PAYLOAD_SIZE);
    
    // Simple exit without printing anything
    // This will help us determine if the segfault is from parameter reading or printing
    
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
