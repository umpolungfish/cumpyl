# Standalone Assembly Test
.global _start

.text
_start:
    # Write debug message
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea msg(%rip), %rsi # message (position-independent)
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
    .ascii "Standalone assembly test executing\n"
msg_len = . - msg