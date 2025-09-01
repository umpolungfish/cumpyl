# Function to evolve CA for multiple steps
# Parameters:
#   %rdi - pointer to initial grid
#   %rsi - pointer to second grid
#   %rdx - grid size in bytes
#   %rcx - number of steps
# Returns:
#   %rax - 0 on success, -1 on error
.global evolve_ca_multiple_steps
evolve_ca_multiple_steps:
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
    jz evolve_error
    test %rsi, %rsi
    jz evolve_error
    test %rdx, %rdx
    jz evolve_error
    test %rcx, %rcx
    jz evolve_success  # 0 steps means nothing to do, but not an error
    
    # Evolve the CA for the specified number of steps
    mov %rcx, %r8  # Step counter
evolve_steps_loop:
    test %r8, %r8
    jz evolve_done
    
    # Evolve current grid to next grid
    mov %rdi, %rdi      # current grid
    mov %rsi, %rsi      # next grid
    mov %rdx, %rdx      # grid size
    call evolve_ca_grid_one_step
    
    test %rax, %rax
    jnz evolve_error
    
    # Swap grids
    mov %rdi, %rbx
    mov %rsi, %rdi
    mov %rbx, %rsi
    
    dec %r8
    jmp evolve_steps_loop
    
evolve_done:
    mov $0, %rax    # Return success
    jmp evolve_cleanup
    
evolve_error:
    mov $-1, %rax   # Return error
    
evolve_success:
    mov $0, %rax    # Return success for 0 steps
    
evolve_cleanup:
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