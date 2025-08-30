/*
 * Minimal Assembly Test for Debug Output
 */

// --- System call numbers for x86-64 Linux ---
#define SYS_EXIT 60
#define SYS_WRITE 1

// --- File descriptors ---
#define STDERR_FD 2

/*
 * Stub entry point
 */
void _start() {
    // Write debug message using inline assembly
    const char msg[] = "Debug message from stub\n";
    __asm__ __volatile__(
        "mov $1, %%rax\n"          // sys_write
        "mov $2, %%rdi\n"          // stderr
        "mov %0, %%rsi\n"          // message
        "mov $25, %%rdx\n"         // length
        "syscall\n"
        :
        : "r" (msg)
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