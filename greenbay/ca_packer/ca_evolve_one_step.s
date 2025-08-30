# Function to evolve CA grid for one step using Rule 30
# Parameters:
#   %rdi - pointer to current grid
#   %rsi - pointer to next grid
#   %rdx - grid size in bytes
# Returns:
#   %rax - 0 on success, -1 on error
.global evolve_ca_grid_one_step
evolve_ca_grid_one_step:
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
    jz evolve_one_error
    test %rsi, %rsi
    jz evolve_one_error
    test %rdx, %rdx
    jz evolve_one_error
    
    # Initialize counters
    xor %r8, %r8    # Byte index
    xor %r9, %r9    # Bit index within byte
    
evolve_byte_loop:
    cmp %rdx, %r8
    jge evolve_done
    
    movb (%rdi,%r8), %bl    # Load current byte
    mov $0, %r10b           # Initialize new byte value
    
    # Process each bit in the byte
    mov $8, %rcx
evolve_bit_loop:
    # Get left neighbor bit
    # If we're at the first bit of the first byte, use 0
    cmp $0, %r8
    jne get_left_from_prev_byte
    cmp $0, %r9
    jne get_left_from_prev_byte
    # First bit of first byte: left neighbor is 0
    mov $0, %r11b
    jmp got_left
get_left_from_prev_byte:
    # Get bit from previous byte
    cmp $0, %r9
    jne get_left_bit_from_prev_byte
    # First bit of current byte: get last bit of previous byte
    mov %r8, %rax
    dec %rax
    movb (%rdi,%rax), %dl
    shr $7, %dl
    mov %dl, %r11b  # Get bit 7 (last bit)
    jmp got_left
get_left_bit_from_prev_byte:
    # Get bit from current byte (previous bit)
    mov %bl, %dl
    mov %r9, %rcx
    dec %rcx
    shr %cl, %dl
    and $1, %dl
    mov %dl, %r11b
got_left:
    
    # Get center bit (current bit)
    mov %bl, %dl
    mov %r9, %rcx
    shr %cl, %dl
    and $1, %dl
    mov %dl, %r10b  # Store center bit temporarily
    
    # Get right neighbor bit
    # If we're at the last bit of the last byte, use 0
    mov %rdx, %rax
    dec %rax
    cmp %rax, %r8
    jb get_right_from_next_byte
    cmp $7, %r9
    ja get_right_from_next_byte
    # Last bit of last byte: right neighbor is 0
    mov $0, %dh
    jmp got_right_correct
get_right_from_next_byte:
    # Get bit from next byte
    cmp $7, %r9
    jb get_right_bit_from_next_byte
    # Last bit of current byte: get first bit of next byte
    mov %r8, %rax
    inc %rax
    movb (%rdi,%rax), %dl
    and $1, %dl  # Get bit 0 (first bit)
    mov %dl, %dh
    jmp got_right_correct
get_right_bit_from_next_byte:
    # Get bit from current byte (next bit)
    mov %bl, %dl
    mov %r9, %rcx
    inc %rcx
    shr %cl, %dl
    and $1, %dl
    mov %dl, %dh
got_right_correct:
    
    # Apply Rule 30: new_state = left XOR (center OR right)
    # Rule 30 table:
    # 111 -> 0
    # 110 -> 0
    # 101 -> 0
    # 100 -> 1
    # 011 -> 1
    # 010 -> 1
    # 001 -> 1
    # 000 -> 0
    #
    # This can be computed as: 
    # new_state = (left & ~center & ~right) | 
    #             (~left & center & right) | 
    #             (~left & center & ~right) | 
    #             (~left & ~center & right)
    #
    # Or more simply: new_state = left XOR (center OR right)
    
    # We have:
    # left in %r11b (from got_left)
    # center in %r10b (stored temporarily)
    # right in %dh (from got_right_correct)
    
    # Compute center OR right
    mov %r10b, %al      # center
    or %dh, %al         # center OR right
    
    # Compute left XOR (center OR right)
    mov %r11b, %dl      # left
    xor %al, %dl        # left XOR (center OR right)
    and $1, %dl         # Ensure result is 0 or 1
    
    # Set the bit in the new byte
    cmp $0, %dl
    je skip_set_bit
    mov %r9, %rcx
    mov $1, %al
    shl %cl, %al
    or %al, %r10b
skip_set_bit:
    
    # Move to next bit
    inc %r9
    cmp $8, %r9
    jl evolve_bit_loop
    
    # Store the new byte
    movb %r10b, (%rsi,%r8)
    
    # Move to next byte
    inc %r8
    xor %r9, %r9  # Reset bit index
    jmp evolve_byte_loop
    
evolve_done:
    mov $0, %rax    # Return success
    jmp evolve_one_cleanup

evolve_one_error:
    mov $-1, %rax   # Return error

evolve_one_cleanup:
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