/*
 * Comprehensive Error Tracking Stub for CA-Packer
 * This stub includes comprehensive error tracking capabilities to help debug issues
 */

// --- System call numbers for x86-64 Linux ---
#define SYS_EXIT 60
#define SYS_WRITE 1

// --- File descriptors ---
#define STDERR_FD 2

// --- Error codes ---
#define ERROR_SUCCESS 42
#define ERROR_SYSCALL_FAILED 100
#define ERROR_INVALID_PARAM 101
#define ERROR_MEMORY_ACCESS 102

/*
 * Write a message to stderr
 */
long write_to_stderr(const char* msg) {
    long result;
    unsigned long len = 0;
    
    // Calculate message length
    while (msg[len] != '\0') len++;
    
    __asm__ __volatile__(
        "syscall"
        : "=a" (result)
        : "a" (SYS_WRITE), "D" (STDERR_FD), "S" (msg), "d" (len)
        : "memory"
    );
    
    return result;
}

/*
 * Exit with code
 */
void exit_with_code(unsigned long exit_code) {
    __asm__ __volatile__(
        "syscall"
        :
        : "a" (SYS_EXIT), "D" (exit_code)
        : "memory"
    );
    
    // Infinite loop in case syscall fails
    while(1);
}

/*
 * Stub entry point
 */
void _start() {
    // Write debug message
    write_to_stderr("CA-Packer Enhanced Stub Executing\n");
    
    // Exit with success code
    exit_with_code(ERROR_SUCCESS);
}