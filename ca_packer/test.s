# Test assembly file
.global _start
.section .text, "ax", @progbits

_start:
    mov $1, %rax
    mov $0, %rdi
    syscall