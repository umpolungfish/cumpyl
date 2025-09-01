# Cellular Automaton (Rule 30) Complete Evolution Implementation
.section .text

# Function to apply Rule 30 to a single cell
# Parameters:
#   %rdi - left neighbor (0 or 1)
#   %rsi - center cell (0 or 1)
#   %rdx - right neighbor (0 or 1)
# Returns:
#   %rax - new state of center cell (0 or 1)
.global apply_rule_30_complete
apply_rule_30_complete:
    push %rbp
    mov %rsp, %rbp
    
    # Rule 30 truth table:
    # 111 -> 0
    # 110 -> 0
    # 101 -> 0
    # 100 -> 1
    # 011 -> 1
    # 010 -> 1
    # 001 -> 1
    # 000 -> 0
    
    # Pack the three cells into a 3-bit value
    # left << 2 | center << 1 | right
    mov %rdi, %rax
    and $1, %rax        # Ensure left is 0 or 1
    shl $2, %rax
    mov %rsi, %rbx
    and $1, %rbx        # Ensure center is 0 or 1
    shl $1, %rbx
    or %rbx, %rax
    mov %rdx, %rbx
    and $1, %rbx        # Ensure right is 0 or 1
    or %rbx, %rax
    
    # Apply Rule 30 using a lookup table approach
    # Rule 30: 00011110 (binary) = 0x1E (hex)
    # Bit positions: 76543210
    #                --------
    #                00011110
    mov $0x1E, %rbx
    bt %rax, %rbx
    setc %al
    
    leave
    ret

# Function to evolve a single row of CA grid for one step
# Parameters:
#   %rdi - pointer to current row
#   %rsi - pointer to next row
#   %rdx - row size in bytes
# Returns:
#   %rax - 0 on success, -1 on error
.global evolve_ca_row_complete
evolve_ca_row_complete:
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
    jz evolve_complete_error
    test %rsi, %rsi
    jz evolve_complete_error
    test %rdx, %rdx
    jz evolve_complete_error
    
    # Process each byte in the row
    xor %r8, %r8        # Byte counter
byte_loop:
    cmp %rdx, %r8
    jge byte_loop_done
    
    # Process each bit in the byte
    mov $0, %r9         # Bit counter
bit_loop:
    cmp $8, %r9
    jge bit_loop_done
    
    # Get left, center, and right neighbors
    xor %rax, %rax      # Left neighbor
    xor %rbx, %rbx      # Center cell
    xor %rcx, %rcx      # Right neighbor
    
    # Left neighbor
    # Handle boundary conditions (fixed, edges are 0)
    cmp $0, %r8
    jne not_first_byte_left
    cmp $0, %r9
    jne not_first_bit_left
    # First bit of first byte - left neighbor is 0
    mov $0, %rax
    jmp left_done
not_first_bit_left:
    # Not first bit - left neighbor is previous bit in same byte
    dec %r9
    bt %r9, (%rdi,%r8)
    setc %al
    inc %r9
    jmp left_done
not_first_byte_left:
    # Not first byte - left neighbor is last bit of previous byte or previous bit
    cmp $0, %r9
    jne not_first_bit_of_byte_left
    # First bit of byte - left neighbor is last bit of previous byte
    dec %r8
    mov $7, %rcx
    bt %rcx, (%rdi,%r8)
    setc %al
    inc %r8
    jmp left_done
not_first_bit_of_byte_left:
    # Not first bit of byte - left neighbor is previous bit
    dec %r9
    bt %r9, (%rdi,%r8)
    setc %al
    inc %r9
left_done:
    
    # Center cell
    bt %r9, (%rdi,%r8)
    setc %bl
    
    # Right neighbor
    # Handle boundary conditions (fixed, edges are 0)
    inc %r8
    cmp %rdx, %r8
    jge right_boundary
    dec %r8
    inc %r9
    cmp $8, %r9
    jge right_boundary_dec
    # Normal case - right neighbor is next bit in same byte
    bt %r9, (%rdi,%r8)
    setc %cl
    dec %r9
    jmp right_done
right_boundary_dec:
    dec %r9
right_boundary:
    dec %r8
    # Right boundary - right neighbor is 0
    mov $0, %rcx
right_done:
    
    # Apply Rule 30 to the three bits
    mov %rax, %rdi      # left
    mov %rbx, %rsi      # center
    mov %rcx, %rdx      # right
    call apply_rule_30_complete
    
    # Store result bit in next row
    test %al, %al
    jz clear_result_bit
    bts %r9, (%rsi,%r8)
    jmp bit_processed
clear_result_bit:
    btr %r9, (%rsi,%r8)
bit_processed:
    
    inc %r9
    jmp bit_loop
bit_loop_done:
    
    inc %r8
    jmp byte_loop
byte_loop_done:
    
    mov $0, %rax        # Return success
    jmp evolve_complete_cleanup
    
evolve_complete_error:
    mov $-1, %rax       # Return error
    
evolve_complete_cleanup:
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

# Function to evolve CA grid for multiple steps
# Parameters:
#   %rdi - pointer to initial grid
#   %rsi - number of steps
#   %rdx - grid size in bytes
#   %rcx - pointer to output grid buffer
# Returns:
#   %rax - 0 on success, -1 on error
.global evolve_ca_grid_complete
evolve_ca_grid_complete:
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
    jz evolve_grid_complete_error
    test %rsi, %rsi
    jz evolve_grid_complete_error
    test %rdx, %rdx
    jz evolve_grid_complete_error
    test %rcx, %rcx
    jz evolve_grid_complete_error
    
    # Allocate memory for two grids
    mov %rdx, %rdi
    call allocate_memory
    test %rax, %rax
    js evolve_grid_complete_error
    mov %rax, %r8           # First grid pointer
    
    mov %rdx, %rdi
    call allocate_memory
    test %rax, %rax
    js evolve_grid_complete_error
    mov %rax, %r9           # Second grid pointer
    
    # Copy initial grid to first grid
    xor %r10, %r10          # Byte counter
copy_initial_loop:
    cmp %rdx, %r10
    jge copy_initial_done
    movb (%rdi,%r10), %bl
    movb %bl, (%r8,%r10)
    inc %r10
    jmp copy_initial_loop
copy_initial_done:
    
    # Evolve the CA for the specified number of steps
    xor %r10, %r10          # Step counter
evolve_steps_loop:
    cmp %rsi, %r10
    jge evolve_steps_done
    
    # Evolve one step
    # Alternate between grids to save memory
    test %r10, %r10
    jz use_grids_1_2
    # Use grids 2 -> 1
    mov %r9, %rdi           # Current grid
    mov %r8, %rsi           # Next grid
    jmp evolve_step_call
use_grids_1_2:
    # Use grids 1 -> 2
    mov %r8, %rdi           # Current grid
    mov %r9, %rsi           # Next grid
evolve_step_call:
    mov %rdx, %rdx          # Grid size
    call evolve_ca_row_complete
    test %rax, %rax
    js evolve_grid_complete_error
    
    inc %r10
    jmp evolve_steps_loop
evolve_steps_done:
    
    # Copy final grid state to output buffer
    # Determine which grid has the final state
    mov %rsi, %rax
    and $1, %rax
    test %rax, %rax
    jz final_in_grid_1
    # Final state is in grid 2
    mov %r9, %rdi           # Source (final grid)
    jmp copy_final_grid
final_in_grid_1:
    # Final state is in grid 1
    mov %r8, %rdi           # Source (final grid)
copy_final_grid:
    mov %rcx, %rsi          # Destination (output buffer)
    xor %rax, %rax          # Byte counter
copy_final_loop:
    cmp %rdx, %rax
    jge copy_final_done
    movb (%rdi,%rax), %bl
    movb %bl, (%rsi,%rax)
    inc %rax
    jmp copy_final_loop
copy_final_done:
    
    # Free allocated memory
    mov %r8, %rdi           # First grid pointer
    mov %rdx, %rsi          # Grid size
    call deallocate_memory
    
    mov %r9, %rdi           # Second grid pointer
    mov %rdx, %rsi          # Grid size
    call deallocate_memory
    
    mov $0, %rax            # Return success
    jmp evolve_grid_complete_cleanup
    
evolve_grid_complete_error:
    mov $-1, %rax           # Return error
    
evolve_grid_complete_cleanup:
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

# Function to generate CA mask from key material - Complete Version
# Parameters:
#   %rdi - pointer to key material (32 bytes)
#   %rsi - block index
#   %rdx - number of CA steps
#   %rcx - mask size in bytes
#   %r8 - pointer to output mask buffer
# Returns:
#   %rax - 0 on success, -1 on error
.global generate_ca_mask_complete_version
generate_ca_mask_complete_version:
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
    jz ca_mask_complete_error
    test %rcx, %rcx
    jz ca_mask_complete_error
    test %r8, %r8
    jz ca_mask_complete_error
    
    # Initialize a CA grid using the key material and block index
    # We'll use a grid size of 256 bytes (2048 bits)
    mov $256, %r9           # Grid size in bytes
    mov %r9, %rdi
    call allocate_memory
    test %rax, %rax
    js ca_mask_complete_error
    mov %rax, %r10          # Grid pointer
    
    # Seed the grid using the key material and block index
    # Copy key material to grid
    xor %rax, %rax          # Byte counter
copy_key_loop:
    cmp $32, %rax
    jge copy_key_done
    cmp %r9, %rax
    jge copy_key_done
    movb (%rdi,%rax), %bl
    movb %bl, (%r10,%rax)
    inc %rax
    jmp copy_key_loop
copy_key_done:
    
    # Fill remaining bytes with zeros
    mov $32, %rax
zero_fill_loop:
    cmp %r9, %rax
    jge zero_fill_done
    movb $0, (%r10,%rax)
    inc %rax
    jmp zero_fill_loop
zero_fill_done:
    
    # Modify some bits based on block index
    # XOR the first few bytes with the block index
    mov %rsi, %rax          # Block index
    mov $0, %rbx            # Byte counter
    
modify_loop:
    cmp $8, %rbx            # Modify up to 8 bytes
    jge modify_done
    cmp %r9, %rbx
    jge modify_done
    
    movb (%r10,%rbx), %dl
    xorb %al, %dl
    movb %dl, (%r10,%rbx)
    
    inc %rbx
    shr $8, %rax            # Shift block index for next byte
    jmp modify_loop
modify_done:
    
    # Evolve the CA for the specified number of steps
    mov %r10, %rdi          # Initial grid
    mov %rdx, %rsi          # Number of steps
    mov %r9, %rdx           # Grid size
    mov %r8, %rcx           # Output buffer (we'll copy the final state here)
    call evolve_ca_grid_complete
    test %rax, %rax
    js ca_mask_complete_error
    
    # Free allocated memory
    mov %r10, %rdi          # Grid pointer
    mov %r9, %rsi           # Grid size
    call deallocate_memory
    
    mov $0, %rax            # Return success
    jmp ca_mask_complete_cleanup
    
ca_mask_complete_error:
    mov $-1, %rax           # Return error
    
ca_mask_complete_cleanup:
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

# Function to allocate memory using mmap
# Parameters:
#   %rdi - size of memory to allocate
# Returns:
#   %rax - pointer to allocated memory (or -1 on error)
.global allocate_memory
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
.global deallocate_memory
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