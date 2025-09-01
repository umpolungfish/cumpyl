# Minimal Test
.global _start
.section .text

_start:
    # Exit with code 42
    mov $60, %rax       # sys_exit
    mov $42, %rdi       # exit code
    syscall
