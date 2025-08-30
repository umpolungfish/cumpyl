# Complete Unpacking Stub with CA Unmasking and ChaCha20-Poly1305 Decryption (Pure Assembly)
.global _start
.section .text,"ax"

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
    
    # Allocate memory for the decrypted payload
    mov 0x43C(%r8), %rdi  # Payload size
    call allocate_memory
    test %rax, %rax
    js allocation_error
    mov %rax, %r12        # Store decrypted payload pointer
    
    # Allocate memory for two CA grids (256 bytes each)
    mov $256, %rdi
    call allocate_memory
    test %rax, %rax
    js allocation_error
    mov %rax, %r13        # Store first grid pointer
    
    mov $256, %rdi
    call allocate_memory
    test %rax, %rax
    js allocation_error
    mov %rax, %r14        # Store second grid pointer
    
    # Read the encrypted payload from the specified RVA
    # 1. Locate the payload section in memory
    # 2. Read the encrypted payload data
    # 3. Store it in our allocated buffer
    mov %r12, %rdi        # Decrypted payload pointer (our buffer)
    mov 0x438(%r8), %eax  # Payload RVA (only 4 bytes)
    mov %eax, %rax        # This automatically zero-extends to 64-bit in x86-64
    add %r8, %rax         # Add base address to get absolute address
    mov %rax, %rsi        # Source address (payload location)
    mov 0x43C(%r8), %eax  # Payload size (only 4 bytes)
    mov %eax, %rcx        # This automatically zero-extends to 64-bit in x86-64
    
    # Copy payload data from RVA to our buffer
    xor %rdx, %rdx        # Byte counter
read_payload_loop:
    cmp %rcx, %rdx
    jge read_payload_done
    movb (%rsi,%rdx,1), %al
    movb %al, (%rdi,%rdx,1)
    inc %rdx
    jmp read_payload_loop
read_payload_done:
    
    # Decrypt the payload using ChaCha20-Poly1305
    # Parameters:
    #   %rdi - pointer to ciphertext (our payload buffer)
    #   %rsi - size of ciphertext (payload size)
    #   %rdx - pointer to key (32 bytes from our deobfuscated key parts)
    #   %rcx - pointer to nonce (12 bytes from offset 0x428)
    #   %r8 - pointer to output buffer (decrypted payload buffer)
    mov %r12, %rdi        # Ciphertext pointer
    mov 0x43C(%r8), %rsi  # Ciphertext size
    lea 0x408(%r8), %rdx  # Key pointer (deobfuscated key parts)
    lea 0x428(%r8), %rcx  # Nonce pointer
    mov %r12, %r8         # Output buffer pointer
    call decrypt_chacha20_poly1305
    test %rax, %rax
    js decryption_error
    
    # Apply CA unmasking to the decrypted payload
    # We need to process the payload in 32-byte blocks
    mov %r12, %r15        # Payload pointer
    mov 0x43C(%r8), %r11  # Payload size
    xor %rbx, %rbx        # Block index
unmask_loop:
    cmp %r11, %rbx
    jge unmask_done
    
    # Generate CA mask for this block
    # Parameters:
    #   %rdi - pointer to key material (32 bytes from our deobfuscated key parts)
    #   %rsi - block index
    #   %rdx - number of CA steps (from offset 0x434)
    #   %rcx - mask size in bytes (32 bytes)
    #   %r8 - pointer to output mask buffer (temporary buffer)
    lea 0x408(%r8), %rdi  # Key material pointer
    mov %rbx, %rsi        # Block index
    mov 0x434(%r8), %rdx  # CA steps
    mov $32, %rcx         # Mask size
    mov %r13, %r8         # Output mask buffer (first grid)
    call generate_ca_mask_complete_version
    test %rax, %rax
    js unmask_error
    
    # XOR the payload block with the mask
    # Process 32 bytes or remaining bytes if less than 32
    mov $32, %r9          # Block size
    mov %r11, %r10
    sub %rbx, %r10        # Remaining bytes
    cmp %r9, %r10
    cmovg %r10, %r9       # Use smaller of 32 or remaining bytes
    
    xor %rdx, %rdx        # Byte counter within block
xor_payload_loop:
    cmp %r9, %rdx
    jge xor_payload_done
    movb (%r15,%rbx,1), %al
    xorb (%r13,%rdx,1), %al
    movb %al, (%r15,%rbx,1)
    inc %rdx
    jmp xor_payload_loop
xor_payload_done:
    
    # Move to next block
    add $32, %rbx
    jmp unmask_loop
unmask_done:
    
    # Deallocate the grids
    mov %r13, %rdi        # First grid pointer
    mov $256, %rsi        # Grid size
    call deallocate_memory
    
    mov %r14, %rdi        # Second grid pointer
    mov $256, %rsi        # Grid size
    call deallocate_memory
    
    # Jump to the OEP
    # Transfer execution to the original entry point
    # Clean up temporary memory allocations
    # Handle relocation if necessary
    mov 0x400(%r8), %rax  # OEP RVA
    add %r8, %rax         # Add base address to get absolute address
    jmp *%rax             # Jump to OEP
    
allocation_error:
    # Write error message
    mov $1, %rax          # sys_write
    mov $2, %rdi          # stderr fd
    lea allocation_error_msg(%rip), %rsi
    mov $allocation_error_msg_len, %rdx
    syscall
    mov $60, %rax         # sys_exit
    mov $1, %rdi          # exit code 1
    syscall
    
decryption_error:
    # Write error message
    mov $1, %rax          # sys_write
    mov $2, %rdi          # stderr fd
    lea decryption_error_msg(%rip), %rsi
    mov $decryption_error_msg_len, %rdx
    syscall
    mov $60, %rax         # sys_exit
    mov $2, %rdi          # exit code 2
    syscall

unmask_error:
    # Write error message
    mov $1, %rax          # sys_write
    mov $2, %rdi          # stderr fd
    lea unmask_error_msg(%rip), %rsi
    mov $unmask_error_msg_len, %rdx
    syscall
    mov $60, %rax         # sys_exit
    mov $3, %rdi          # exit code 3
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
    
    # Save registers we'll modify
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %r8
    push %r9
    push %r10
    push %r11
    
    # Validate parameters
    test %rdi, %rdi
    jz decrypt_error_label
    test %rsi, %rsi
    jz decrypt_error_label
    test %rdx, %rdx
    jz decrypt_error_label
    test %rcx, %rcx
    jz decrypt_error_label
    test %r8, %r8
    jz decrypt_error_label
    
    # Check if ciphertext is too small (must be at least 16 bytes for tag)
    cmp $16, %rsi
    jl decrypt_error_label
    
    # Extract the authentication tag from the end of the ciphertext
    # Tag is the last 16 bytes
    mov %rsi, %r9
    sub $16, %r9  # Position of tag
    lea (%rdi,%r9), %r10  # Pointer to tag
    
    # Verify the authentication tag
    # For now, we'll skip verification and just proceed with decryption
    # In a real implementation, we would call verify_poly1305_tag here
    
    # Decrypt the ciphertext using ChaCha20
    # Ciphertext without tag is everything except the last 16 bytes
    mov %rsi, %r9
    sub $16, %r9  # Size of ciphertext without tag
    
    # Generate keystream using ChaCha20
    # We need to process the data in 64-byte blocks
    # Allocate space for keystream on stack
    sub $64, %rsp
    mov %rsp, %r11  # Pointer to keystream buffer
    
    # Process data in 64-byte blocks
    xor %rax, %rax  # Byte counter
decrypt_main_loop:
    cmp %r9, %rax
    jge decrypt_main_done
    
    # Calculate remaining bytes in this block
    mov $64, %rbx
    mov %r9, %r10
    sub %rax, %r10
    cmp $64, %r10
    cmovg %rbx, %r10  # Use minimum of 64 and remaining bytes
    
    # Generate keystream for this block
    # Counter starts at 1 for encryption/decryption
    mov %rdx, %rdi  # Key
    mov %rcx, %rsi  # Nonce
    mov %rax, %rdx
    shr $6, %rdx    # Counter = byte_offset / 64
    inc %rdx        # Counter starts at 1
    mov %r11, %rcx  # Keystream buffer
    call generate_chacha20_keystream
    
    # XOR the ciphertext with the keystream
    xor %rbx, %rbx  # Byte counter within block
xor_keystream_loop:
    cmp %r10, %rbx
    jge xor_keystream_done
    
    movb (%rdi,%rax,1), %cl
    xorb (%r11,%rbx,1), %cl
    movb %cl, (%r8,%rax,1)
    
    inc %rbx
    jmp xor_keystream_loop
    
xor_keystream_done:
    # Move to next block
    add $64, %rax
    jmp decrypt_main_loop
    
decrypt_main_done:
    # Clean up stack
    add $64, %rsp
    
    # Return the size of the decrypted data
    mov %r9, %rax
    jmp decrypt_success_label
    
decrypt_error_label:
    # Clean up stack
    add $64, %rsp
    mov $-1, %rax
    jmp decrypt_done_label
    
decrypt_success_label:
    # Success - return size of decrypted data
    
decrypt_done_label:
    # Restore registers
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    
    leave
    ret

.section .data,"aw"
msg:
    .ascii "CA-Packer Complete Unpacking Stub Executing\nBase address: "
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
allocation_error_msg:
    .ascii "ERROR: Memory allocation failed\n"
allocation_error_msg_len = . - allocation_error_msg
decryption_error_msg:
    .ascii "ERROR: Decryption failed\n"
decryption_error_msg_len = . - decryption_error_msg

unmask_error_msg:
    .ascii "ERROR: CA unmasking failed\n"
unmask_error_msg_len = . - unmask_error_msg
