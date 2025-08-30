# Memory Management Functions for Unpacking Stub
.section .text

# Function to allocate memory using mmap
# Parameters:
#   %rdi - size of memory to allocate
# Returns:
#   %rax - pointer to allocated memory (or -1 on error)
allocate_memory:
    push %rbp
    mov %rsp, %rbp
    
    # Save registers
    push %rdi
    push %rsi
    push %rdx
    push %r10
    push %r8
    push %r9
    
    # mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
    # addr = NULL (0)
    # length = size (passed in %rdi)
    # prot = PROT_READ | PROT_WRITE (0x3)
    # flags = MAP_PRIVATE | MAP_ANONYMOUS (0x22)
    # fd = -1
    # offset = 0
    
    mov %rdi, %rsi          # length
    mov $0, %rdi            # addr = NULL
    mov $0x3, %rdx          # prot = PROT_READ | PROT_WRITE
    mov $0x22, %r10         # flags = MAP_PRIVATE | MAP_ANONYMOUS
    mov $-1, %r8            # fd = -1
    mov $0, %r9             # offset = 0
    mov $9, %rax            # sys_mmap
    syscall
    
    # Restore registers
    pop %r9
    pop %r8
    pop %r10
    pop %rdx
    pop %rsi
    pop %rdi
    
    leave
    ret

# Function to deallocate memory using munmap
# Parameters:
#   %rdi - pointer to memory to deallocate
#   %rsi - size of memory to deallocate
# Returns:
#   %rax - 0 on success, -1 on error
deallocate_memory:
    push %rbp
    mov %rsp, %rbp
    
    # Save registers
    push %rdi
    push %rsi
    push %rdx
    
    # munmap(void *addr, size_t length)
    mov %rdi, %rdi          # addr (passed in %rdi)
    mov %rsi, %rsi          # length (passed in %rsi)
    mov $11, %rax           # sys_munmap
    syscall
    
    # Restore registers
    pop %rdx
    pop %rsi
    pop %rdi
    
    leave
    ret
