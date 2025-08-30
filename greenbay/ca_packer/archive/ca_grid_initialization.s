# Function to initialize CA grid with key material and block index
# Parameters:
#   %rdi - pointer to key material (32 bytes)
#   %rsi - block index
#   %rdx - grid size in bytes
#   %rcx - pointer to grid buffer
# Returns:
#   %rax - 0 on success, -1 on error
.global initialize_ca_grid_with_key_material
initialize_ca_grid_with_key_material:
    push %rbp
    mov %rsp, %rbp
    
    # Save registers we'll modify
    push %rbx
    push %rcx
    push %rdx
    push %r8
    push %r9
    push %r10
    push %r11
    
    # Validate parameters
    test %rdi, %rdi
    jz init_grid_error
    test %rdx, %rdx
    jz init_grid_error
    test %rcx, %rcx
    jz init_grid_error
    
    # Initialize the grid using the key material and block index
    # For simplicity, we'll copy the key material to the beginning of the grid
    # and use the block index to modify some bits
    
    # Copy key material to grid (up to 32 bytes or grid size, whichever is smaller)
    xor %rax, %rax  # Byte counter
copy_key_loop:
    cmp $32, %rax
    jge copy_key_done
    cmp %rdx, %rax
    jge copy_key_done
    movb (%rdi,%rax), %bl
    movb %bl, (%rcx,%rax)
    inc %rax
    jmp copy_key_loop
copy_key_done:
    
    # Fill remaining bytes with a pattern derived from the block index
    mov $32, %rax
fill_remaining_loop:
    cmp %rdx, %rax
    jge fill_remaining_done
    
    # Derive a byte from the block index and position
    mov %rsi, %rbx          # Block index
    add %rax, %rbx          # Add position
    xor %rbx, %rbx          # Mix bits
    rol $3, %rbx            # Rotate left by 3
    and $0xFF, %rbx         # Mask to byte
    movb %bl, (%rcx,%rax)
    
    inc %rax
    jmp fill_remaining_loop
fill_remaining_done:
    
    mov $0, %rax    # Return success
    jmp init_grid_cleanup
    
init_grid_error:
    mov $-1, %rax   # Return error
    
init_grid_cleanup:
    # Restore registers
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdx
    pop %rcx
    pop %rbx
    
    leave
    ret