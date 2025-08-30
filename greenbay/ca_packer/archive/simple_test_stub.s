# Simple test stub
.global _start
.section .text,"ax"

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

.section .data,"aw"
msg:
    .ascii "Simple test stub executing\n"
msg_len = . - msg