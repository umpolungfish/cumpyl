/*
 * Simple Exit Stub for CA-Packer
 * This stub just exits with code 42 to verify basic execution
 */

// --- System call numbers for x86-64 Linux ---
#define SYS_EXIT 60

/*
 * Stub entry point
 */
void _start() {
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