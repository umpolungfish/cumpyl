# Function to allocate memory for two CA grids
# Parameters:
#   %rdi - size of each grid in bytes
#   %rsi - pointer to first grid pointer variable
#   %rdx - pointer to second grid pointer variable
# Returns:
#   %rax - 0 on success, -1 on error
.global allocate_two_ca_grids
allocate_two_ca_grids:
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
    jz alloc_grids_error
    test %rsi, %rsi
    jz alloc_grids_error
    test %rdx, %rdx
    jz alloc_grids_error
    
    # Allocate memory for first grid
    mov %rdi, %rdi          # grid size
    call allocate_memory_complete
    
    # Check if allocation failed
    cmp $-1, %rax
    je alloc_grids_error
    
    # Store first grid pointer
    mov %rax, (%rsi)
    
    # Allocate memory for second grid
    mov %rdi, %rdi          # grid size
    call allocate_memory_complete
    
    # Check if allocation failed
    cmp $-1, %rax
    je alloc_grids_cleanup_first
    
    # Store second grid pointer
    mov %rax, (%rdx)
    
    # Return success
    mov $0, %rax
    jmp alloc_grids_cleanup
    
alloc_grids_cleanup_first:
    # Deallocate first grid
    mov (%rsi), %rdi        # first grid pointer
    mov %rdi, %rsi          # grid size (same as passed in %rdi)
    call deallocate_memory_complete
    
    # Clear first grid pointer
    mov $0, (%rsi)
    
alloc_grids_error:
    mov $-1, %rax           # Return error
    
alloc_grids_cleanup:
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

# Function to deallocate memory for two CA grids
# Parameters:
#   %rdi - pointer to first grid
#   %rsi - pointer to second grid
#   %rdx - size of each grid in bytes
# Returns:
#   %rax - 0 on success, -1 on error
.global deallocate_two_ca_grids
deallocate_two_ca_grids:
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
    jz dealloc_grids_error
    test %rsi, %rsi
    jz dealloc_grids_error
    test %rdx, %rdx
    jz dealloc_grids_error
    
    # Deallocate first grid
    mov %rdi, %rdi          # first grid pointer
    mov %rdx, %rsi          # grid size
    call deallocate_memory_complete
    
    # Check if deallocation failed
    cmp $-1, %rax
    je dealloc_grids_error
    
    # Deallocate second grid
    mov %rsi, %rdi          # second grid pointer
    mov %rdx, %rsi          # grid size
    call deallocate_memory_complete
    
    # Check if deallocation failed
    cmp $-1, %rax
    je dealloc_grids_error
    
    # Return success
    mov $0, %rax
    jmp dealloc_grids_cleanup
    
dealloc_grids_error:
    mov $-1, %rax           # Return error
    
dealloc_grids_cleanup:
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