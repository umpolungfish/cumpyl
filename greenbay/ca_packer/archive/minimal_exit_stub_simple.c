/*
 * Simple Minimal Exit Stub
 * This is a very simple stub that just exits with a fixed code.
 */

// System call numbers for x86-64 Linux
#define SYS_EXIT 60

void _start() {
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