/*
 * Simple Print and Exit Stub for CA-Packer
 * This stub prints a message and exits
 */

#include <stdint.h>

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
    char msg[] = "Hello from CA-Packer stub!\n";
    int msg_len = 26;  // Corrected length
    
    // Write message to stdout
    __asm__ __volatile__(
        "mov $1, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov %1, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall\n"
        :
        : "r" (msg), "r" ((long)msg_len)
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