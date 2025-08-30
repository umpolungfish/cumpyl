# Simple Assembly Test
.global _start

.text
_start:
    # Write debug message
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    mov $msg, %rsi      # message
    mov $32, %rdx       # message length
    syscall

    # Exit with code 42
    mov $60, %rax       # sys_exit
    mov $42, %rdi       # exit code
    syscall

    # Infinite loop in case syscall fails
    jmp .

.data
msg:
    .ascii "Simple assembly test executing\n"