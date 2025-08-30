# Enhanced Parameter Reading Stub (Pure Assembly)
.global _start
.section .text
.code64

_start:
    # Get base address of the stub
    lea (_start)(%rip), %r8
    # Mask to page boundary (4KB pages)
    and $~0xFFF, %r8
    
    # Write debug message
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea msg(%rip), %rsi # message
    mov $msg_len, %rdx  # message length
    syscall
    
    # Report base address
    mov %r8, %rsi
    call write_hex
    
    # Try to read a parameter from offset 0x400
    mov 0x400(%r8), %r9
    
    # Report parameter value
    mov %r9, %rsi
    call write_hex
    
    # Exit with code 42
    mov $60, %rax       # sys_exit
    mov $42, %rdi       # exit code
    syscall

# Function to write a hex value to stderr
write_hex:
    push %rbp
    mov %rsp, %rbp
    sub $32, %rsp       # Allocate space for buffer
    
    # Convert value in %rsi to hex string
    mov %rsi, %rax      # Value to convert
    lea -32(%rbp), %rdi # Buffer address
    mov $16, %rcx       # 16 characters for 64-bit value
    
convert_loop:
    rol $4, %rax        # Rotate left by 4 bits
    mov %rax, %r9
    and $0xF, %r9       # Get low 4 bits
    cmp $9, %r9
    jle numeric
    add $7, %r9         # Adjust for A-F
numeric:
    add $48, %r9        # Convert to ASCII
    mov %r9b, (%rdi)    # Store character
    inc %rdi
    loop convert_loop
    
    # Write "0x" prefix
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea prefix(%rip), %rsi # "0x" prefix
    mov $2, %rdx        # 2 characters
    syscall
    
    # Write hex value
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea -32(%rbp), %rsi # Buffer address
    mov $16, %rdx       # 16 characters
    syscall
    
    # Write newline
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea newline(%rip), %rsi # newline
    mov $1, %rdx        # 1 character
    syscall
    
    leave
    ret

.section .data
msg:
    .ascii "CA-Packer Enhanced Parameter Reading Stub Executing\nBase address: "
msg_len = . - msg
prefix:
    .ascii "0x"
newline:
    .ascii "\n"
param_msg:
    .ascii "Parameter value: "
param_msg_len = . - param_msg