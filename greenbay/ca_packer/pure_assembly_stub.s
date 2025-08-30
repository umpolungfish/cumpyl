# Enhanced Error Tracking Stub (Pure Assembly)
.global _start
.section .text
_start:
    # Write debug message
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea msg(%rip), %rsi # message
    mov $msg_len, %rdx  # message length
    syscall

    # Exit with code 42
    mov $60, %rax       # sys_exit
    mov $42, %rdi       # exit code
    syscall

    # Infinite loop in case syscall fails
    jmp .

.section .data
msg:
    .ascii "CA-Packer Enhanced Error Tracking Stub Executing\n"
msg_len = . - msg