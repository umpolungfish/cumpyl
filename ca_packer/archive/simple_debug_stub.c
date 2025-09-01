/*
 * Simple Debug Stub for CA-Packer
 * This stub just prints a message and exits
 */

// System call numbers for x86-64 Linux
#define SYS_WRITE 1
#define SYS_EXIT 60

// File descriptors
#define STDOUT 1

void _start() {
    // Message to print
    char msg[] = "Debug stub executed\\n";
    int msg_len = 22;
    
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