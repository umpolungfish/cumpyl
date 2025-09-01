# Enhanced Error Tracking Stub (Pure Assembly)
.global enhanced_error_tracking_stub
.section .text
enhanced_error_tracking_stub:
    # Write debug message
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea msg(%rip), %rsi # message
    mov $msg_len, %rdx  # message length
    syscall

    # Return (don't exit)
    ret

.section .data
msg:
    .ascii "CA-Packer Enhanced Error Tracking Stub Executing\n"
msg_len = . - msg