# This file is intended to be preprocessed with the C Preprocessor (gcc -E)
# to allow for conditional compilation of debug messages.
# Define DEBUG=1 for debug builds, or RELEASE=1 for release builds.

.global _start
.section .text, "ax", @progbits

_start:
    # Use an explicit 5-byte near jump to guarantee a fixed size, preventing
    # the assembler from choosing a smaller encoding that would mismatch the
    # STUB_PARAMETER_OFFSET in the packer.
    .byte 0xe9
    .long main_code_start - (. + 4)

# Reserve space for parameters. The packer will embed data here.
# The offset of this area from _start must match STUB_PARAMETER_OFFSET in packer.py
parameter_area:
    .zero 0x48  # Reserve 72 bytes for parameters
parameter_area_end:

main_code_start:
    # --- Anti-debugging: ptrace check --- # Disabled for testing
    # mov $101, %rax        # sys_ptrace
    # mov $0, %rdi          # PTRACE_TRACEME
    # mov $0, %rsi
    # mov $0, %rdx
    # syscall
    # test %rax, %rax       # Check if result is negative
    # js debugger_detected  # If so, a debugger is attached

    # Get base address of the parameter area to use as a reference
    lea parameter_area(%rip), %r8
    
    # Calculate the dynamic load base address to handle ASLR.
    # The packer provides the RVA of the stub section.
    # dynamic_base = runtime_address_of_param_area - RVA_of_param_area
    # RVA_of_param_area = RVA_of_stub_section + offset_of_param_area
    movq 0x40(%r8), %r9      # r9 = RVA of stub section
    add $5, %r9             # r9 = RVA of parameter_area (offset is 5 bytes for jmp)
    mov %r8, %r10           # r10 = runtime address of parameter_area
    sub %r9, %r10           # r10 = dynamic load base address
    
#ifdef DEBUG
    # Write debug message
    lea msg(%rip), %rdi
    mov $msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea msg(%rip), %rsi # message
    mov $msg_len, %rdx  # message length
    syscall
    lea msg(%rip), %rdi
    mov $msg_len, %rsi
    call decrypt_string # Re-encrypt
    
    # Report base address
    mov %r8, %rsi
    call write_hex
    
    # OEP is no longer used.
    
    # Read and report Key part 1 (8 bytes at parameter_area)
    mov (%r8), %r9
    lea key1_msg(%rip), %rdi
    mov $key1_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea key1_msg(%rip), %rsi
    mov $key1_msg_len, %rdx
    syscall
    lea key1_msg(%rip), %rdi
    mov $key1_msg_len, %rsi
    call decrypt_string # Re-encrypt
    mov %r9, %rsi
    call write_hex
    
    # Read and report Key part 2 (8 bytes at offset 0x8)
    mov 0x8(%r8), %r9
    lea key2_msg(%rip), %rdi
    mov $key2_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea key2_msg(%rip), %rsi
    mov $key2_msg_len, %rdx
    syscall
    lea key2_msg(%rip), %rdi
    mov $key2_msg_len, %rsi
    call decrypt_string # Re-encrypt
    mov %r9, %rsi
    call write_hex
    
    # Read and report Key part 3 (8 bytes at offset 0x10)
    mov 0x10(%r8), %r9
    lea key3_msg(%rip), %rdi
    mov $key3_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea key3_msg(%rip), %rsi
    mov $key3_msg_len, %rdx
    syscall
    lea key3_msg(%rip), %rdi
    mov $key3_msg_len, %rsi
    call decrypt_string # Re-encrypt
    mov %r9, %rsi
    call write_hex
    
    # Read and report Key part 4 (8 bytes at offset 0x18)
    mov 0x18(%r8), %r9
    lea key4_msg(%rip), %rdi
    mov $key4_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea key4_msg(%rip), %rsi
    mov $key4_msg_len, %rdx
    syscall
    lea key4_msg(%rip), %rdi
    mov $key4_msg_len, %rsi
    call decrypt_string # Re-encrypt
    mov %r9, %rsi
    call write_hex
    
    # Read and report Nonce (12 bytes at parameter_area + 0x20)
    mov 0x20(%r8), %r9
    lea nonce_msg(%rip), %rdi
    mov $nonce_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea nonce_msg(%rip), %rsi
    mov $nonce_msg_len, %rdx
    syscall
    lea nonce_msg(%rip), %rdi
    mov $nonce_msg_len, %rsi
    call decrypt_string # Re-encrypt
    mov %r9, %rsi
    call write_hex
    
    # Read and report CA Steps (4 bytes at parameter_area + 0x2C)
    movl 0x2C(%r8), %eax
    mov %rax, %r9
    lea ca_steps_msg(%rip), %rdi
    mov $ca_steps_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea ca_steps_msg(%rip), %rsi
    mov $ca_steps_msg_len, %rdx
    syscall
    lea ca_steps_msg(%rip), %rdi
    mov $ca_steps_msg_len, %rsi
    call decrypt_string # Re-encrypt
    mov %r9, %rsi
    call write_hex
    
    # Read and report Payload Section RVA (8 bytes at parameter_area + 0x30)
    movq 0x30(%r8), %r9
    lea payload_rva_msg(%rip), %rdi
    mov $payload_rva_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea payload_rva_msg(%rip), %rsi
    mov $payload_rva_msg_len, %rdx
    syscall
    lea payload_rva_msg(%rip), %rdi
    mov $payload_rva_msg_len, %rsi
    call decrypt_string # Re-encrypt
    mov %r9, %rsi
    call write_hex
    
    # Read and report Payload Size (8 bytes at parameter_area + 0x38)
    movq 0x38(%r8), %r9
    lea payload_size_msg(%rip), %rdi
    mov $payload_size_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea payload_size_msg(%rip), %rsi
    mov $payload_size_msg_len, %rdx
    syscall
    lea payload_size_msg(%rip), %rdi
    mov $payload_size_msg_len, %rsi
    call decrypt_string # Re-encrypt
    mov %r9, %rsi
    call write_hex

    # Read and report Stub Section RVA (8 bytes at parameter_area + 0x40)
    movq 0x40(%r8), %r9
    lea stub_rva_msg(%rip), %rdi
    mov $stub_rva_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea stub_rva_msg(%rip), %rsi
    mov $stub_rva_msg_len, %rdx
    syscall
    lea stub_rva_msg(%rip), %rdi
    mov $stub_rva_msg_len, %rsi
    call decrypt_string # Re-encrypt
    mov %r9, %rsi
    call write_hex
#endif /* DEBUG */
    
    # Deobfuscate the key parts
    # XOR each key part with the fixed key (0xCABEFEBEEFBEADDE)
    mov $0xCABEFEBEEFBEADDE, %rax  # Fixed obfuscation key, use %rax to avoid clobbering %r10 (dynamic base)
    
    # Deobfuscate key part 1
    mov (%r8), %r11
    xor %rax, %r11
    mov %r11, (%r8)  # Store deobfuscated key part 1 back
    
    # Deobfuscate key part 2
    mov 0x8(%r8), %r11
    xor %rax, %r11
    mov %r11, 0x8(%r8)  # Store deobfuscated key part 2 back
    
    # Deobfuscate key part 3
    mov 0x10(%r8), %r11
    xor %rax, %r11
    mov %r11, 0x10(%r8)  # Store deobfuscated key part 3 back
    
    # Deobfuscate key part 4
    mov 0x18(%r8), %r11
    xor %rax, %r11
    mov %r11, 0x18(%r8)  # Store deobfuscated key part 4 back
    
#ifdef DEBUG
    # Report deobfuscated key parts
    lea deobfuscated_key_msg(%rip), %rdi
    mov $deobfuscated_key_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea deobfuscated_key_msg(%rip), %rsi
    mov $deobfuscated_key_msg_len, %rdx
    syscall
    lea deobfuscated_key_msg(%rip), %rdi
    mov $deobfuscated_key_msg_len, %rsi
    call decrypt_string # Re-encrypt
    
    # Report deobfuscated key part 1
    mov (%r8), %r9
    lea key1_msg(%rip), %rdi
    mov $key1_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea key1_msg(%rip), %rsi
    mov $key1_msg_len, %rdx
    syscall
    lea key1_msg(%rip), %rdi
    mov $key1_msg_len, %rsi
    call decrypt_string # Re-encrypt
    mov %r9, %rsi
    call write_hex
    
    # Report deobfuscated key part 2
    mov 0x8(%r8), %r9
    lea key2_msg(%rip), %rdi
    mov $key2_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea key2_msg(%rip), %rsi
    mov $key2_msg_len, %rdx
    syscall
    lea key2_msg(%rip), %rdi
    mov $key2_msg_len, %rsi
    call decrypt_string # Re-encrypt
    mov %r9, %rsi
    call write_hex
    
    # Report deobfuscated key part 3
    mov 0x10(%r8), %r9
    lea key3_msg(%rip), %rdi
    mov $key3_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea key3_msg(%rip), %rsi
    mov $key3_msg_len, %rdx
    syscall
    lea key3_msg(%rip), %rdi
    mov $key3_msg_len, %rsi
    call decrypt_string # Re-encrypt
    mov %r9, %rsi
    call write_hex
    
    # Report deobfuscated key part 4
    mov 0x18(%r8), %r9
    lea key4_msg(%rip), %rdi
    mov $key4_msg_len, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea key4_msg(%rip), %rsi
    mov $key4_msg_len, %rdx
    syscall
    lea key4_msg(%rip), %rdi
    mov $key4_msg_len, %rsi
    call decrypt_string # Re-encrypt
    mov %r9, %rsi
    call write_hex
#endif /* DEBUG */
    
    # Allocate memory for the decrypted payload
    movq 0x38(%r8), %rdi  # Payload size
    call allocate_memory
    test %rax, %rax
    js allocation_error
    mov %rax, %r12        # Store decrypted payload pointer
    
    # Allocate memory for two CA grids (32 bytes each for 256 bits)
    mov $32, %rdi
    call allocate_memory
    test %rax, %rax
    js allocation_error
    mov %rax, %r13        # Store first grid pointer
    
    mov $32, %rdi
    call allocate_memory
    test %rax, %rax
    js allocation_error
    mov %rax, %r14        # Store second grid pointer
    
    # Read the encrypted payload from its RVA, adjusted by the dynamic base address.
    movq 0x30(%r8), %rsi  # rsi = RVA of payload section
    add %r10, %rsi        # rsi = absolute VA of payload section
    
    # Copy the payload using rep movsb
    mov %r12, %rdi        # Destination: our allocated buffer
    movq 0x38(%r8), %rcx  # Count: payload size
    rep movsb
    
    # Decrypt the payload using ChaCha20-Poly1305
    # Parameters:
    #   %rdi - pointer to ciphertext (our payload buffer)
    #   %rsi - size of ciphertext (payload size)
    #   %rdx - pointer to key (32 bytes from our deobfuscated key parts)
    #   %rcx - pointer to nonce (12 bytes from parameter_area + 0x20)
    #   %r8 - pointer to output buffer (decrypted payload buffer)
    mov %r12, %rdi        # Ciphertext pointer
    movq 0x38(%r8), %rsi  # Ciphertext size
    lea (%r8), %rdx       # Key pointer (deobfuscated key parts)
    lea 0x20(%r8), %rcx   # Nonce pointer
    mov %r12, %r8         # Output buffer pointer
    call decrypt_chacha20
    test %rax, %rax
    js decryption_error
    
    # Apply CA unmasking to the decrypted payload
    # We need to process the payload in 32-byte blocks
    mov %r12, %r15        # Payload pointer
    movq 0x38(%r8), %r11  # Payload size
    xor %rbx, %rbx        # Block index
unmask_loop:
    cmp %r11, %rbx
    jge unmask_done
    
    # Generate CA mask for this block
    # Parameters:
    #   %rdi - pointer to key material (32 bytes)
    #   %rsi - block index
    #   %rdx - number of CA steps
    #   %rcx - mask size in bytes (32 bytes)
    #   %r8  - pointer to grid_1 buffer
    #   %r9  - pointer to grid_2 buffer
    #   Output mask will be in grid_1 buffer (%r13).
    lea (%r8), %rdi       # Key material pointer
    mov %rbx, %rsi        # Block index
    movl 0x2C(%r8), %edx  # CA steps (4 bytes)
    mov $32, %rcx         # Mask size
    mov %r13, %r8         # grid_1
    mov %r14, %r9         # grid_2
    call generate_ca_mask_complete_version
    test %rax, %rax
    js unmask_error
    
    # XOR the payload block with the mask
    # Process 32 bytes or remaining bytes if less than 32
    mov $32, %r9          # Block size
    mov %r11, %r10
    sub %rbx, %r10        # Remaining bytes
    cmp %r9, %r10
    cmovl %r10, %r9       # Use smaller of 32 or remaining bytes
    
    lea (%r15, %rbx, 1), %rax
    xor %rdx, %rdx        # Byte counter within block
xor_payload_loop:
    cmp %r9, %rdx
    jge xor_payload_done
    movb (%rax,%rdx,1), %al
    xorb (%r13,%rdx,1), %al
    movb %al, (%rax,%rdx,1)
    inc %rdx
    jmp xor_payload_loop
xor_payload_done:
    
    # Move to next block
    add $32, %rbx
    jmp unmask_loop
unmask_done:
    
    # Deallocate the grids
    mov %r13, %rdi        # First grid pointer
    mov $32, %rsi         # Grid size
    call deallocate_memory
    
    mov %r14, %rdi        # Second grid pointer
    mov $32, %rsi         # Grid size
    call deallocate_memory
    
    # Execute the decrypted payload from memory using memfd_create and fexecve
    # 1. Create an anonymous file in memory with memfd_create
    mov $319, %rax          # sys_memfd_create
    lea memfd_name(%rip), %rdi # name for the file
    mov $1, %rsi            # MFD_CLOEXEC flag
    syscall
    test %rax, %rax
    js fexecve_error         # If rax is negative, it's an error
    mov %rax, %r13          # Save file descriptor in r13
    
    # 2. Write the decrypted payload to the memory file
    mov $1, %rax            # sys_write
    mov %r13, %rdi          # fd from memfd_create
    mov %r12, %rsi          # decrypted payload buffer
    movq 0x38(%r8), %rdx    # payload size
    syscall
    test %rax, %rax
    js fexecve_error         # Check for write error
    
    # 3. Execute the file with fexecve
    # We build argv = ["payload", NULL] and envp = [NULL] on the stack.
    pushq $0                # envp NULL terminator
    mov %rsp, %rdx          # rdx = &envp[0]
    
    pushq $0                # argv NULL terminator
    lea memfd_name(%rip), %rax
    push %rax               # argv[0] = "payload"
    mov %rsp, %rsi          # rsi = &argv[0]
    
    mov $322, %rax          # sys_fexecve
    mov %r13, %rdi          # fd
    syscall
    
    # If fexecve succeeds, this code is never reached. If it fails, we fall through.
    # Restore stack before erroring out. We pushed 3 items (24 bytes)
    add $24, %rsp
    jmp fexecve_error
    
allocation_error:
    # Write error message
#ifdef DEBUG
    lea allocation_error_msg(%rip), %rdi
    mov $allocation_error_msg_len, %rsi
    call decrypt_string
#endif
    mov $1, %rax          # sys_write
    mov $2, %rdi          # stderr fd
    lea allocation_error_msg(%rip), %rsi
    mov $allocation_error_msg_len, %rdx
    syscall
#ifdef DEBUG
    # No need to re-encrypt; exiting
#endif
    mov $60, %rax         # sys_exit
    mov $1, %rdi          # exit code 1
    syscall
    
decryption_error:
    # Write error message
#ifdef DEBUG
    lea decryption_error_msg(%rip), %rdi
    mov $decryption_error_msg_len, %rsi
    call decrypt_string
#endif
    mov $1, %rax          # sys_write
    mov $2, %rdi          # stderr fd
    lea decryption_error_msg(%rip), %rsi
    mov $decryption_error_msg_len, %rdx
    syscall
#ifdef DEBUG
    # No need to re-encrypt; exiting
#endif
    mov $60, %rax         # sys_exit
    mov $2, %rdi          # exit code 2
    syscall

unmask_error:
    # Write error message
#ifdef DEBUG
    lea unmask_error_msg(%rip), %rdi
    mov $unmask_error_msg_len, %rsi
    call decrypt_string
#endif
    mov $1, %rax          # sys_write
    mov $2, %rdi          # stderr fd
    lea unmask_error_msg(%rip), %rsi
    mov $unmask_error_msg_len, %rdx
    syscall
#ifdef DEBUG
    # No need to re-encrypt; exiting
#endif
    mov $60, %rax         # sys_exit
    mov $3, %rdi          # exit code 3
    syscall

debugger_detected:
    # A debugger was detected. Exit silently.
    mov $60, %rax         # sys_exit
    mov $4, %rdi          # exit code 4
    syscall

fexecve_error:
    # Write error message
#ifdef DEBUG
    lea fexecve_error_msg(%rip), %rdi
    mov $fexecve_error_msg_len, %rsi
    call decrypt_string
#endif
    mov $1, %rax          # sys_write
    mov $2, %rdi          # stderr fd
    lea fexecve_error_msg(%rip), %rsi
    mov $fexecve_error_msg_len, %rdx
    syscall
#ifdef DEBUG
    # No need to re-encrypt; exiting
#endif
    mov $60, %rax         # sys_exit
    mov $5, %rdi          # exit code 5
    syscall

#ifdef DEBUG
# Function to decrypt/encrypt a string in-place using single-byte XOR
# Parameters:
#   %rdi - pointer to string
#   %rsi - length of string
decrypt_string:
    push %rdi
    push %rsi
    push %rcx
    push %rax
    mov %rsi, %rcx      # loop counter
    mov $0xAA, %al      # XOR key
decrypt_loop:
    cmp $0, %rcx
    je decrypt_done
    xor %al, (%rdi)
    inc %rdi
    dec %rcx
    jmp decrypt_loop
decrypt_done:
    pop %rax
    pop %rcx
    pop %rsi
    pop %rdi
    ret

# Function to write a hex value to stderr
write_hex:
    push %rbp
    mov %rsp, %rbp
    sub $32, %rsp       # Allocate space for buffer
    push %r12           # Callee-saved register
    
    # Convert value in %rsi to hex string
    mov %rsi, %rax      # Value to convert
    lea -1(%rbp), %rdi  # Buffer address (start from the end)
    mov $16, %rcx       # 16 characters for 64-bit value
    
convert_loop:
    test %rcx, %rcx     # Check if we've processed all 16 characters
    jz convert_done
    mov %rax, %r9
    and $0xF, %r9       # Get low 4 bits
    cmp $9, %r9
    jle numeric
    add $7, %r9         # Adjust for A-F
numeric:
    add $48, %r9        # Convert to ASCII
    mov %r9b, (%rdi)    # Store character
    dec %rdi
    shr $4, %rax        # Shift right by 4 bits
    dec %rcx
    jmp convert_loop
convert_done:
    inc %rdi            # Adjust pointer to start of string
    mov %rdi, %r12      # Save pointer to hex string
    
    # Write "0x" prefix
    lea prefix(%rip), %rdi
    mov $2, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea prefix(%rip), %rsi # "0x" prefix
    mov $2, %rdx        # 2 characters
    syscall
    lea prefix(%rip), %rdi
    mov $2, %rsi
    call decrypt_string # Re-encrypt
    
    # Write hex value
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    mov %r12, %rsi      # Use saved pointer to hex string
    mov $16, %rdx       # 16 characters
    syscall
    
    # Write newline
    lea newline(%rip), %rdi
    mov $1, %rsi
    call decrypt_string
    mov $1, %rax        # sys_write
    mov $2, %rdi        # stderr fd
    lea newline(%rip), %rsi # newline
    mov $1, %rdx        # 1 character
    syscall
    lea newline(%rip), %rdi
    mov $1, %rsi
    call decrypt_string # Re-encrypt
    
    pop %r12
    leave
    ret
#endif /* DEBUG */

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
    # prot = PROT_READ | PROT_WRITE | PROT_EXEC (0x7)
    # flags = MAP_PRIVATE | MAP_ANONYMOUS (0x22)
    # fd = -1
    # offset = 0
    
    mov %rdi, %rsi          # length
    mov $0, %rdi            # addr = NULL
    mov $0x7, %rdx          # prot = PROT_READ | PROT_WRITE | PROT_EXEC
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

# Function to decrypt data using ChaCha20 stream cipher
# Parameters:
#   %rdi - pointer to ciphertext
#   %rsi - size of ciphertext
#   %rdx - pointer to key (32 bytes)
#   %rcx - pointer to nonce (12 bytes)
#   %r8 - pointer to output buffer
# Returns:
#   %rax - size of decrypted data (or -1 on error)
decrypt_chacha20:
    push %rbp
    mov %rsp, %rbp
    
    # Save registers we'll modify. We push 12 registers here which, combined
    # with `push %rbp`, keeps the stack 16-byte aligned for function calls.
    push %r15
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    
    # Validate parameters
    test %rdi, %rdi
    jz decrypt_error_label
    test %rsi, %rsi
    jz decrypt_success_label # Size 0 is a valid success case
    test %rdx, %rdx
    jz decrypt_error_label
    test %rcx, %rcx
    jz decrypt_error_label
    test %r8, %r8
    jz decrypt_error_label
    
    # Total size of data to decrypt is in %rsi
    mov %rsi, %r9
    
    # Save key and nonce pointers into callee-saved registers
    mov %rdx, %r12      # key pointer
    mov %rcx, %r13      # nonce pointer
    mov %rdi, %r14      # ciphertext pointer
    
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
    mov %r12, %rdi  # Key
    mov %r13, %rsi  # Nonce
    mov %rax, %rdx
    shr $6, %rdx    # Counter = byte_offset / 64
    inc %rdx        # Counter starts at 1
    mov %r11, %rcx  # Keystream buffer
    call generate_chacha20_keystream
    
    # XOR the ciphertext with the keystream
    lea (%r14, %rax, 1), %rcx
    lea (%r8, %rax, 1), %rdx
    xor %rbx, %rbx  # Byte counter within block
xor_keystream_loop:
    cmp %r10, %rbx
    jge xor_keystream_done
    
    movb (%rcx,%rbx,1), %al
    xorb (%r11,%rbx,1), %al
    movb %al, (%rdx,%rbx,1)
    
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
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    pop %r15
    
    leave
    ret

# Function to generate a CA mask using Rule 30
# Parameters:
#   %rdi - pointer to key material (32 bytes)
#   %rsi - block index
#   %rdx - number of CA steps
#   %rcx - mask size in bytes (32 bytes) - currently unused
#   %r8  - pointer to current_grid buffer (also output buffer)
#   %r9  - pointer to next_grid buffer
# Returns:
#   %rax - 0 on success, -1 on error
generate_ca_mask_complete_version:
    push %rbp
    mov %rsp, %rbp
    
    # Save registers. We save 8 registers here to keep the stack 16-byte
    # aligned for calls within this function. %rbx is used as a loop counter
    # and must be preserved for the caller.
    push %rax; push %rbx
    push %r10; push %r11; push %r12
    push %r13; push %r14; push %r15
    
    # Store parameters & save original destination
    mov %r8, %r15   # Save original destination buffer pointer
    mov %rdi, %r10  # key material
    mov %rsi, %r11  # block index
    mov %rdx, %r12  # num_steps
    mov %r8, %r13   # current_grid
    mov %r9, %r14   # next_grid

    # --- 1. Seeding ---
    # Create initial grid by XORing key with block index.
    mov %r11d, %eax
    mov %r13, %rdi; mov %r10, %rsi; mov $32, %rcx; rep movsb
    xor %rbx, %rbx
seed_loop:
    cmp $8, %rbx; jge seed_loop_done
    xor %eax, (%r13, %rbx, 4)
    inc %rbx; jmp seed_loop
seed_loop_done:

    # --- 2. Evolve CA ---
    mov %r12, %rcx
evolve_loop:
    test %rcx, %rcx; jz evolve_done
    
    push %rcx
    mov %r14, %rdi
    xor %rax, %rax
    mov $4, %rcx
    rep stosq
    pop %rcx
    
    mov $256, %r10 # Number of bits in the grid
    xor %rbx, %rbx
cell_loop:
    cmp %r10, %rbx; jge cell_loop_done
    
    mov %rbx, %rsi; dec %rsi; mov %r13, %rdi; call get_bit
    mov %al, %dl
    
    mov %rbx, %rsi; mov %r13, %rdi; call get_bit
    mov %al, %dh
    
    mov %rbx, %rsi; inc %rsi; mov %r13, %rdi; call get_bit
    
    or %dh, %al
    xor %dl, %al
    
    mov %r14, %rdi; mov %rbx, %rsi; call set_bit

    inc %rbx; jmp cell_loop
cell_loop_done:
    xchg %r13, %r14
    dec %rcx; jmp evolve_loop
evolve_done:

    # --- 3. Finalize ---
    # The final mask is in %r13. Copy to original destination if needed.
    cmp %r13, %r15; je mask_in_place
    
    mov %r15, %rdi; mov %r13, %rsi; mov $32, %rcx; rep movsb
    
mask_in_place:
    mov $0, %rax
    pop %r15; pop %r14; pop %r13; pop %r12
    pop %r11; pop %r10
    pop %rbx; pop %rax
    leave
    ret
    
# Helper: get_bit(grid_ptr in %rdi, bit_index in %rsi) -> bit in %al
get_bit:
    cmp $256, %rsi; jae get_bit_boundary
    test %rsi, %rsi; js get_bit_boundary
    push %rcx; push %rdx
    mov %rsi, %rax; mov %rsi, %rdx
    shr $3, %rax
    and $7, %rdx
    movb (%rdi, %rax, 1), %cl
    
    # Use a lookup table for powers of 2
    lea bit_masks(%rip), %rax
    movb (%rax, %rdx, 1), %al
    test %cl, %al
    setnz %al
    pop %rdx; pop %rcx
    ret
    
get_bit_boundary:
    xor %al, %al
    ret
    
# Bit masks for powers of 2 (0 to 7)
bit_masks:
    .byte 1, 2, 4, 8, 16, 32, 64, 128
    
# Helper: set_bit(grid_ptr in %rdi, bit_index in %rsi, value in %al)
set_bit:
    push %rbx; push %rcx; push %rdx
    mov %rsi, %rdx; mov %rsi, %rcx
    shr $3, %rdx
    and $7, %rcx
    mov $1, %ebx  # Use 32-bit register
    shl %cl, %bl  # Shift 8-bit portion of 32-bit register
    test %al, %al; jz set_bit_zero
set_bit_one:
    or %bl, (%rdi, %rdx, 1); jmp set_bit_done
set_bit_zero:
    not %bl; and %bl, (%rdi, %rdx, 1)
set_bit_done:
    pop %rdx; pop %rcx; pop %rbx; ret

# Helper function for ChaCha20: Quarter Round
# Standard ABI: state base ptr in %r10 (callee-saved), indices in %rdi, %rsi, %rdx, %rcx
# Clobbers: %rax, %r8, %r9, %r11, and all argument registers.
chacha_qr:
    # Arguments are passed in registers: %rdi, %rsi, %rdx, %rcx for indices a, b, c, d.
    
    # Load state values into scratch registers:
    #   %r8d  -> a
    #   %r9d  -> b
    #   %r11d -> c
    #   %eax  -> d
    movl (%r10, %rdi, 4), %r8d      # a = state[index_a]
    movl (%r10, %rsi, 4), %r9d      # b = state[index_b]
    movl (%r10, %rdx, 4), %r11d     # c = state[index_c]
    movl (%r10, %rcx, 4), %eax      # d = state[index_d]
    
    # Perform quarter round operations
    addl %r9d, %r8d; xorl %r8d, %eax; roll $16, %eax      # a+=b; d^=a; d<<<=16
    addl %eax, %r11d; xorl %r11d, %r9d; roll $12, %r9d   # c+=d; b^=c; b<<<=12
    addl %r9d, %r8d; xorl %r8d, %eax; roll $8, %eax      # a+=b; d^=a; d<<<=8
    addl %eax, %r11d; xorl %r11d, %r9d; roll $7, %r9d    # c+=d; b^=c; b<<<=7

    # Store results back to state matrix
    movl %r8d, (%r10, %rdi, 4)
    movl %r9d, (%r10, %rsi, 4)
    movl %r11d, (%r10, %rdx, 4)
    movl %eax, (%r10, %rcx, 4)
    
    ret

# Function to generate a ChaCha20 keystream (full implementation)
# Parameters:
#   %rdi - pointer to key (32 bytes)
#   %rsi - pointer to nonce (12 bytes)
#   %rdx - counter (64-bit, but only lower 32-bit used)
#   %rcx - pointer to keystream buffer (64 bytes)
# Returns:
#   (none, keystream written to buffer)
generate_chacha20_keystream:
    push %rbp
    mov %rsp, %rbp
    sub $144, %rsp      # 64 for state, 64 for copy, 16 for alignment
    
    # Save registers. %rbx is not used in this function. We push 6 registers
    # here to keep the stack 16-byte aligned for the call to chacha_qr.
    push %r10; push %r11; push %r12
    push %r13; push %r14; push %r15
    
    # Store parameters before they are clobbered by rep movsl etc.
    mov %rdi, %r12      # r12 = key ptr
    mov %rsi, %r13      # r13 = nonce ptr
    mov %rdx, %r14      # r14 = counter
    mov %rcx, %r15      # r15 = output buffer ptr

    # --- 1. Initialize ChaCha20 State Matrix ---
    # State matrix at -128(%rbp), initial copy at -64(%rbp)
    lea -128(%rbp), %r10 # %r10 = state base pointer
    
    # Constants
    movl $0x61707865, (%r10)
    movl $0x3320646e, 4(%r10)
    movl $0x79622d32, 8(%r10)
    movl $0x6b206574, 12(%r10)
    
    # Key (copy 32 bytes)
    mov %r12, %rsi          # src: key pointer
    lea 16(%r10), %rdi      # dst: state[4]
    mov $8, %rcx
    rep movsl               # copy 8 dwords
    
    # Counter
    mov %r14d, %eax         # counter is in r14
    movl %eax, 48(%r10)
    
    # Nonce (copy 12 bytes)
    mov %r13, %rsi          # src: nonce pointer
    lea 52(%r10), %rdi      # dst: state[13]
    mov $3, %rcx
    rep movsl               # copy 3 dwords

    # Make a copy of the initial state for the final addition
    lea -64(%rbp), %rdi     # dst: copy buffer
    mov %r10, %rsi          # src: state buffer
    mov $16, %rcx
    rep movsl               # copy 16 dwords
    
    # --- 2. Run 20 Rounds (10 double rounds) ---
    mov $10, %r11           # Loop counter
chacha_round_loop:
    # Column Round
    mov $0, %edi; mov $4, %esi; mov $8, %edx; mov $12, %ecx; call chacha_qr
    mov $1, %edi; mov $5, %esi; mov $9, %edx; mov $13, %ecx; call chacha_qr
    mov $2, %edi; mov $6, %esi; mov $10, %edx; mov $14, %ecx; call chacha_qr
    mov $3, %edi; mov $7, %esi; mov $11, %edx; mov $15, %ecx; call chacha_qr
    
    # Diagonal Round
    mov $0, %edi; mov $5, %esi; mov $10, %edx; mov $15, %ecx; call chacha_qr
    mov $1, %edi; mov $6, %esi; mov $11, %edx; mov $12, %ecx; call chacha_qr
    mov $2, %edi; mov $7, %esi; mov $8, %edx; mov $13, %ecx; call chacha_qr
    mov $3, %edi; mov $4, %esi; mov $9, %edx; mov $14, %ecx; call chacha_qr
    
    dec %r11
    jnz chacha_round_loop
    
    # --- 3. Add Initial State to Final State ---
    lea -64(%rbp), %rsi     # src: initial state copy
    mov %r10, %rdi          # dst: final state
    mov $16, %rcx           # 16 dwords
add_state_loop:
    movl (%rsi), %eax
    addl %eax, (%rdi)
    add $4, %rsi
    add $4, %rdi
    dec %rcx
    jnz add_state_loop
    
    # --- 4. Serialize to Output Buffer ---
    mov %r15, %rdi          # dst: output buffer
    mov %r10, %rsi          # src: final state
    mov $16, %rcx
    rep movsl               # copy 16 dwords
    
    # Restore registers and stack
    pop %r15; pop %r14; pop %r13; pop %r12
    pop %r11; pop %r10
    
    leave
    ret

.section .data, "aw", @progbits
#ifdef DEBUG
msg:
    .byte 0xcd, 0xca, 0xdf, 0xdc, 0xcb, 0xd0, 0xd3, 0xde, 0xaa, 0xcd, 0xc6, 0xd7, 0xd3, 0xcc, 0xd4, 0xaa, 0xd9, 0xdc, 0xca, 0xcb, 0xd8, 0xca, 0xdc, 0xd5, 0xdd, 0xaa, 0xcb, 0xdd, 0xdd, 0xaa, 0xcb, 0xcd, 0xd3, 0xcb, 0xc6, 0xdd, 0xaa, 0xca, 0xce, 0xcd, 0xaa, 0xda, 0xc6, 0xcf, 0xcb, 0xd3, 0xc4, 0xaa, 0xc4, 0xd5, 0x9a, 0xda, 0xcb, 0xd4, 0xcb, 0xaa, 0xc6, 0xc4, 0xc4, 0xd3, 0xde, 0xd4, 0xd4, 0xda, 0xaa
msg_len = . - msg
prefix:
    .byte 0x9a, 0x88
newline:
    .byte 0xa0
# oep_msg is no longer used
key1_msg:
    .byte 0xcd, 0xde, 0xd8, 0xaa, 0xd0, 0xc6, 0xd3, 0xdd, 0xaa, 0xbb, 0xda, 0xaa
key1_msg_len = . - key1_msg
key2_msg:
    .byte 0xcd, 0xde, 0xd8, 0xaa, 0xd0, 0xc6, 0xd3, 0xdd, 0xaa, 0xb8, 0xda, 0xaa
key2_msg_len = . - key2_msg
key3_msg:
    .byte 0xcd, 0xde, 0xd8, 0xaa, 0xd0, 0xc6, 0xd3, 0xdd, 0xaa, 0xb9, 0xda, 0xaa
key3_msg_len = . - key3_msg
key4_msg:
    .byte 0xcd, 0xde, 0xd8, 0xaa, 0xd0, 0xc6, 0xd3, 0xdd, 0xaa, 0xba, 0xda, 0xaa
key4_msg_len = . - key4_msg
nonce_msg:
    .byte 0xce, 0xc6, 0xdc, 0xc9, 0xde, 0xda, 0xaa
nonce_msg_len = . - nonce_msg
ca_steps_msg:
    .byte 0xcd, 0xca, 0xaa, 0xcb, 0xdd, 0xde, 0xd1, 0xd4, 0xda, 0xaa
ca_steps_msg_len = . - ca_steps_msg
payload_rva_msg:
    .byte 0xd0, 0xc6, 0xd8, 0xcc, 0xc6, 0xc4, 0xaa, 0xd2, 0xdc, 0xca, 0xda, 0xaa
payload_rva_msg_len = . - payload_rva_msg
payload_size_msg:
    .byte 0xd0, 0xc6, 0xd8, 0xcc, 0xc6, 0xc4, 0xaa, 0xcb, 0xca, 0xce, 0xde, 0xda, 0xaa
payload_size_msg_len = . - payload_size_msg
stub_rva_msg:
    .byte 0xcb, 0xdd, 0xd2, 0xc4, 0xaa, 0xd2, 0xdc, 0xca, 0xda, 0xaa
stub_rva_msg_len = . - stub_rva_msg
deobfuscated_key_msg:
    .byte 0xcc, 0xde, 0xc6, 0xc3, 0xd2, 0xd4, 0xc9, 0xc6, 0xdd, 0xde, 0xc4, 0xaa, 0xcd, 0xde, 0xd8, 0xaa, 0xd0, 0xc6, 0xd3, 0xdd, 0xd4, 0xda, 0x9a
deobfuscated_key_msg_len = . - deobfuscated_key_msg
#endif /* DEBUG */
allocation_error_msg:
    .byte 0xcb, 0xc0, 0xc0, 0xc5, 0xc9, 0xcb, 0xde, 0xc3, 0xc5, 0xc4, 0x8a, 0xcd, 0xd8, 0xd8, 0xc5, 0xd8, 0xaa
allocation_error_msg_len = . - allocation_error_msg
decryption_error_msg:
    .byte 0xce, 0xcd, 0xc9, 0xd8, 0xdf, 0xda, 0xde, 0xc3, 0xc5, 0xc4, 0x8a, 0xcd, 0xd8, 0xd8, 0xc5, 0xd8, 0xaa
decryption_error_msg_len = . - decryption_error_msg
unmask_error_msg:
    .byte 0xdf, 0xc4, 0xc7, 0xcb, 0xd9, 0xc1, 0x8a, 0xcd, 0xd8, 0xd8, 0xc5, 0xd8, 0xaa
unmask_error_msg_len = . - unmask_error_msg
memfd_name:
    .string "payload"
fexecve_error_msg:
    .byte 0xcc, 0xcd, 0xd2, 0xcd, 0xc9, 0xdc, 0xcd, 0x8a, 0xcd, 0xd8, 0xd8, 0xc5, 0xd8, 0xaa
fexecve_error_msg_len = . - fexecve_error_msg


