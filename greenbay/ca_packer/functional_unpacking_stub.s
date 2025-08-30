# Functional Unpacking Stub (Pure Assembly)
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
    
    # Read and report OEP (8 bytes at offset 0x400)
    mov 0x400(%r8), %r9
    lea oep_msg(%rip), %rsi
    mov $oep_msg_len, %rdx
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    syscall
    mov %r9, %rsi
    call write_hex
    
    # Read and report Key part 1 (8 bytes at offset 0x408)
    mov 0x408(%r8), %r9
    lea key1_msg(%rip), %rsi
    mov $key1_msg_len, %rdx
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    syscall
    mov %r9, %rsi
    call write_hex
    
    # Read and report Key part 2 (8 bytes at offset 0x410)
    mov 0x410(%r8), %r9
    lea key2_msg(%rip), %rsi
    mov $key2_msg_len, %rdx
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    syscall
    mov %r9, %rsi
    call write_hex
    
    # Read and report Key part 3 (8 bytes at offset 0x418)
    mov 0x418(%r8), %r9
    lea key3_msg(%rip), %rsi
    mov $key3_msg_len, %rdx
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    syscall
    mov %r9, %rsi
    call write_hex
    
    # Read and report Key part 4 (8 bytes at offset 0x420)
    mov 0x420(%r8), %r9
    lea key4_msg(%rip), %rsi
    mov $key4_msg_len, %rdx
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    syscall
    mov %r9, %rsi
    call write_hex
    
    # Read and report Nonce (12 bytes at offset 0x428)
    mov 0x428(%r8), %r9
    lea nonce_msg(%rip), %rsi
    mov $nonce_msg_len, %rdx
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    syscall
    mov %r9, %rsi
    call write_hex
    
    # Read and report CA Steps (4 bytes at offset 0x434)
    mov 0x434(%r8), %r9
    lea ca_steps_msg(%rip), %rsi
    mov $ca_steps_msg_len, %rdx
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    syscall
    mov %r9, %rsi
    call write_hex
    
    # Read and report Payload Section RVA (4 bytes at offset 0x438)
    mov 0x438(%r8), %r9
    lea payload_rva_msg(%rip), %rsi
    mov $payload_rva_msg_len, %rdx
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    syscall
    mov %r9, %rsi
    call write_hex
    
    # Read and report Payload Size (4 bytes at offset 0x43C)
    mov 0x43C(%r8), %r9
    lea payload_size_msg(%rip), %rsi
    mov $payload_size_msg_len, %rdx
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    syscall
    mov %r9, %rsi
    call write_hex
    
    # For now, just exit with code 42
    # In a real implementation, we would:
    # 1. Allocate memory for the decrypted payload
    # 2. Read the encrypted payload from the specified RVA
    # 3. Decrypt the payload using the key and nonce
    # 4. Apply CA unmasking to the decrypted payload
    # 5. Jump to the OEP
    
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
    .ascii "CA-Packer Functional Unpacking Stub Executing\nBase address: "
msg_len = . - msg
prefix:
    .ascii "0x"
newline:
    .ascii "\n"
oep_msg:
    .ascii "OEP: "
oep_msg_len = . - oep_msg
key1_msg:
    .ascii "Key Part 1: "
key1_msg_len = . - key1_msg
key2_msg:
    .ascii "Key Part 2: "
key2_msg_len = . - key2_msg
key3_msg:
    .ascii "Key Part 3: "
key3_msg_len = . - key3_msg
key4_msg:
    .ascii "Key Part 4: "
key4_msg_len = . - key4_msg
nonce_msg:
    .ascii "Nonce: "
nonce_msg_len = . - nonce_msg
ca_steps_msg:
    .ascii "CA Steps: "
ca_steps_msg_len = . - ca_steps_msg
payload_rva_msg:
    .ascii "Payload RVA: "
payload_rva_msg_len = . - payload_rva_msg
payload_size_msg:
    .ascii "Payload Size: "
payload_size_msg_len = . - payload_size_msg
