# Enhanced Unpacking Stub with ChaCha20 Decryption (Pure Assembly)
.global _start
.section .text

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
    
    # Deobfuscate the key parts
    # XOR each key part with the fixed key (0xCABEFEBEEFBEADDE)
    mov $0xCABEFEBEEFBEADDE, %r10  # Fixed obfuscation key
    
    # Deobfuscate key part 1
    mov 0x408(%r8), %r11
    xor %r10, %r11
    mov %r11, 0x408(%r8)  # Store deobfuscated key part 1 back
    
    # Deobfuscate key part 2
    mov 0x410(%r8), %r11
    xor %r10, %r11
    mov %r11, 0x410(%r8)  # Store deobfuscated key part 2 back
    
    # Deobfuscate key part 3
    mov 0x418(%r8), %r11
    xor %r10, %r11
    mov %r11, 0x418(%r8)  # Store deobfuscated key part 3 back
    
    # Deobfuscate key part 4
    mov 0x420(%r8), %r11
    xor %r10, %r11
    mov %r11, 0x420(%r8)  # Store deobfuscated key part 4 back
    
    # Report deobfuscated key parts
    lea deobfuscated_key_msg(%rip), %rsi
    mov $deobfuscated_key_msg_len, %rdx
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    syscall
    
    # Report deobfuscated key part 1
    mov 0x408(%r8), %r9
    lea key1_msg(%rip), %rsi
    mov $key1_msg_len, %rdx
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    syscall
    mov %r9, %rsi
    call write_hex
    
    # Report deobfuscated key part 2
    mov 0x410(%r8), %r9
    lea key2_msg(%rip), %rsi
    mov $key2_msg_len, %rdx
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    syscall
    mov %r9, %rsi
    call write_hex
    
    # Report deobfuscated key part 3
    mov 0x418(%r8), %r9
    lea key3_msg(%rip), %rsi
    mov $key3_msg_len, %rdx
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    syscall
    mov %r9, %rsi
    call write_hex
    
    # Report deobfuscated key part 4
    mov 0x420(%r8), %r9
    lea key4_msg(%rip), %rsi
    mov $key4_msg_len, %rdx
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

# Function to allocate memory using mmap
# Parameters:
#   %rdi - size of memory to allocate
# Returns:
#   %rax - pointer to allocated memory (or -1 on error)
allocate_memory:
    push %rbp
    mov %rsp, %rbp
    
    # Save registers
    push %rdi
    push %rsi
    push %rdx
    push %r10
    push %r8
    push %r9
    
    # mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
    # addr = NULL (0)
    # length = size (passed in %rdi)
    # prot = PROT_READ | PROT_WRITE (0x3)
    # flags = MAP_PRIVATE | MAP_ANONYMOUS (0x22)
    # fd = -1
    # offset = 0
    
    mov %rdi, %rsi          # length
    mov $0, %rdi            # addr = NULL
    mov $0x3, %rdx          # prot = PROT_READ | PROT_WRITE
    mov $0x22, %r10         # flags = MAP_PRIVATE | MAP_ANONYMOUS
    mov $-1, %r8            # fd = -1
    mov $0, %r9             # offset = 0
    mov $9, %rax            # sys_mmap
    syscall
    
    # Restore registers
    pop %r9
    pop %r8
    pop %r10
    pop %rdx
    pop %rsi
    pop %rdi
    
    leave
    ret

# Function to deallocate memory using munmap
# Parameters:
#   %rdi - pointer to memory to deallocate
#   %rsi - size of memory to deallocate
# Returns:
#   %rax - 0 on success, -1 on error
deallocate_memory:
    push %rbp
    mov %rsp, %rbp
    
    # Save registers
    push %rdi
    push %rsi
    push %rdx
    
    # munmap(void *addr, size_t length)
    mov %rdi, %rdi          # addr (passed in %rdi)
    mov %rsi, %rsi          # length (passed in %rsi)
    mov $11, %rax           # sys_munmap
    syscall
    
    # Restore registers
    pop %rdx
    pop %rsi
    pop %rdi
    
    leave
    ret

# Function to decrypt data using ChaCha20-Poly1305
# Parameters:
#   %rdi - pointer to ciphertext
#   %rsi - size of ciphertext
#   %rdx - pointer to key (32 bytes)
#   %rcx - pointer to nonce (12 bytes)
#   %r8 - pointer to output buffer
# Returns:
#   %rax - size of decrypted data (or -1 on error)
decrypt_chacha20_poly1305:
    push %rbp
    mov %rsp, %rbp
    
    # Save registers
    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %r8
    push %r9
    push %r10
    push %r11
    
    # For now, just return an error since we haven't implemented the full ChaCha20-Poly1305
    # In a real implementation, we would:
    # 1. Validate parameters
    # 2. Extract the authentication tag from the end of the ciphertext
    # 3. Verify the authentication tag
    # 4. Decrypt the ciphertext using ChaCha20
    # 5. Return the size of the decrypted data
    
    mov $-1, %rax  # Return error for now
    
    # Restore registers
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi
    
    leave
    ret

# Function to apply CA unmasking
# Parameters:
#   %rdi - pointer to data
#   %rsi - size of data
#   %rdx - pointer to key material (32 bytes)
#   %rcx - block index
# Returns:
#   %rax - 0 on success, -1 on error
apply_ca_unmasking:
    push %rbp
    mov %rsp, %rbp
    
    # Save registers
    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %r8
    push %r9
    push %r10
    push %r11
    
    # For now, just return success since we haven't implemented the full CA unmasking
    # In a real implementation, we would:
    # 1. Validate parameters
    # 2. Generate mask using CA (Rule 30)
    # 3. XOR the data with the mask
    # 4. Return success
    
    mov $0, %rax  # Return success for now
    
    # Restore registers
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi
    
    leave
    ret

.section .data
msg:
    .ascii "CA-Packer Enhanced Unpacking Stub with ChaCha20 Executing\nBase address: "
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
deobfuscated_key_msg:
    .ascii "Deobfuscated Key Parts:\n"
deobfuscated_key_msg_len = . - deobfuscated_key_msg
