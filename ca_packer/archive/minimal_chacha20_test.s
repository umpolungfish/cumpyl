# Minimal ChaCha20 Core Test
.section .text
.global _start

_start:
    # Simple test - just exit with code 42
    mov $60, %rax       # sys_exit
    mov $42, %rdi       # exit code
    syscall
