# ChaCha20 Stream Cipher Implementation (Core Functions)
.section .text

# ChaCha20 constants
.equ CHACHA20_CONSTANT_0, 0x61707865  # "expa"
.equ CHACHA20_CONSTANT_1, 0x3320646e  # "nd 3"
.equ CHACHA20_CONSTANT_2, 0x79622d32  # "2-by"
.equ CHACHA20_CONSTANT_3, 0x6b206574  # "te k"

# Function to initialize ChaCha20 state
# Parameters:
#   %rdi - pointer to key (32 bytes)
#   %rsi - pointer to nonce (12 bytes)
#   %rdx - counter value
#   %rcx - pointer to state buffer (64 bytes)
.global initialize_chacha20_state
initialize_chacha20_state:
    push %rbp
    mov %rsp, %rbp
    
    # Save registers we'll modify
    push %rax
    push %rbx
    push %rdx
    push %r8
    push %r9
    push %r10
    push %r11
    
    # Initialize the state array (16 32-bit words)
    # Constants (4 words)
    movl $CHACHA20_CONSTANT_0, (%rcx)
    movl $CHACHA20_CONSTANT_1, 4(%rcx)
    movl $CHACHA20_CONSTANT_2, 8(%rcx)
    movl $CHACHA20_CONSTANT_3, 12(%rcx)
    
    # Key (8 words)
    movl (%rdi), %eax
    movl %eax, 16(%rcx)
    movl 4(%rdi), %eax
    movl %eax, 20(%rcx)
    movl 8(%rdi), %eax
    movl %eax, 24(%rcx)
    movl 12(%rdi), %eax
    movl %eax, 28(%rcx)
    movl 16(%rdi), %eax
    movl %eax, 32(%rcx)
    movl 20(%rdi), %eax
    movl %eax, 36(%rcx)
    movl 24(%rdi), %eax
    movl %eax, 40(%rcx)
    movl 28(%rdi), %eax
    movl %eax, 44(%rcx)
    
    # Counter (1 word)
    movl %edx, 48(%rcx)
    
    # Nonce (3 words)
    movl (%rsi), %eax
    movl %eax, 52(%rcx)
    movl 4(%rsi), %eax
    movl %eax, 56(%rcx)
    movl 8(%rsi), %eax
    movl %eax, 60(%rcx)
    
    # Restore registers
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdx
    pop %rbx
    pop %rax
    
    leave
    ret

# Function to perform a single ChaCha20 quarter round
# Parameters:
#   %rdi - pointer to state array
#   %rsi - index a
#   %rdx - index b
#   %rcx - index c
#   %r8 - index d
.global quarter_round
quarter_round:
    push %rbp
    mov %rsp, %rbp
    
    # Save registers we'll modify
    push %rax
    push %rbx
    push %rdx
    push %rcx
    push %r8
    push %r9
    push %r10
    push %r11
    
    # Calculate byte offsets
    mov %rsi, %r9
    shl $2, %r9  # Multiply by 4 for 32-bit words
    
    mov %rdx, %r10
    shl $2, %r10  # Multiply by 4 for 32-bit words
    
    mov %rcx, %r11
    shl $2, %r11  # Multiply by 4 for 32-bit words
    
    mov %r8, %rax
    shl $2, %rax  # Multiply by 4 for 32-bit words
    
    # Load values
    movl (%rdi,%r9), %ebx   # a
    movl (%rdi,%r10), %edx  # b
    movl (%rdi,%r11), %ecx  # c
    movl (%rdi,%rax), %r8d  # d
    
    # a += b; d ^= a; d <<<= 16;
    addl %edx, %ebx
    xorl %ebx, %r8d
    roll $16, %r8d
    
    # c += d; b ^= c; b <<<= 12;
    addl %r8d, %ecx
    xorl %ecx, %edx
    roll $12, %edx
    
    # a += b; d ^= a; d <<<= 8;
    addl %edx, %ebx
    xorl %ebx, %r8d
    roll $8, %r8d
    
    # c += d; b ^= c; b <<<= 7;
    addl %r8d, %ecx
    xorl %ecx, %edx
    roll $7, %edx
    
    # Store values back
    movl %ebx, (%rdi,%r9)
    movl %edx, (%rdi,%r10)
    movl %ecx, (%rdi,%r11)
    movl %r8d, (%rdi,%rax)
    
    # Restore registers
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rcx
    pop %rdx
    pop %rbx
    pop %rax
    
    leave
    ret

# Function to perform ChaCha20 rounds
# Parameters:
#   %rdi - pointer to state array
.global chacha20_rounds
chacha20_rounds:
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
    
    # Perform 20 rounds (10 column rounds + 10 diagonal rounds)
    mov $10, %r9  # Number of double rounds
    
double_round_loop:
    # Column round
    mov $0, %rsi
    mov $4, %rdx
    mov $8, %rcx
    mov $12, %r8
    call quarter_round
    
    mov $1, %rsi
    mov $5, %rdx
    mov $9, %rcx
    mov $13, %r8
    call quarter_round
    
    mov $2, %rsi
    mov $6, %rdx
    mov $10, %rcx
    mov $14, %r8
    call quarter_round
    
    mov $3, %rsi
    mov $7, %rdx
    mov $11, %rcx
    mov $15, %r8
    call quarter_round
    
    # Diagonal round
    mov $0, %rsi
    mov $5, %rdx
    mov $10, %rcx
    mov $15, %r8
    call quarter_round
    
    mov $1, %rsi
    mov $6, %rdx
    mov $11, %rcx
    mov $12, %r8
    call quarter_round
    
    mov $2, %rsi
    mov $7, %rdx
    mov $8, %rcx
    mov $13, %r8
    call quarter_round
    
    mov $3, %rsi
    mov $4, %rdx
    mov $9, %rcx
    mov $14, %r8
    call quarter_round
    
    dec %r9
    jnz double_round_loop
    
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

# Function to generate ChaCha20 keystream block
# Parameters:
#   %rdi - pointer to key (32 bytes)
#   %rsi - pointer to nonce (12 bytes)
#   %rdx - counter value
#   %rcx - pointer to output buffer (64 bytes)
.global generate_chacha20_keystream
generate_chacha20_keystream:
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
    
    # Allocate space for state on stack
    sub $64, %rsp
    mov %rsp, %r8  # r8 points to state
    
    # Initialize state
    call initialize_chacha20_state
    
    # Perform ChaCha20 rounds
    mov %r8, %rdi
    call chacha20_rounds
    
    # Add original state to result and store in output buffer
    mov $0, %r9
add_loop:
    movl (%r8,%r9,4), %eax
    addl 64(%rsp,%r9,4), %eax  # Add original state (was saved on stack)
    movl %eax, (%rcx,%r9,4)
    inc %r9
    cmp $16, %r9
    jl add_loop
    
    # Restore stack and registers
    add $64, %rsp
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

# Function to XOR data with ChaCha20 keystream
# Parameters:
#   %rdi - pointer to input data
#   %rsi - pointer to keystream
#   %rdx - size of data
#   %rcx - pointer to output buffer
.global xor_with_keystream
xor_with_keystream:
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
    
    # Process data in 64-byte blocks
    xor %r8, %r8  # Byte counter
    xor %r9, %r9  # Block counter
    
xor_loop:
    # Check if we've processed all data
    cmp %rdx, %r8
    jge xor_done
    
    # Calculate remaining bytes in this block
    mov $64, %r10
    mov %rdx, %r11
    sub %r8, %r11
    cmp $64, %r11
    cmovg %r10, %r11  # Use minimum of 64 and remaining bytes
    
    # XOR bytes in this block
    xor %rax, %rax
xor_byte_loop:
    cmp %r11, %rax
    jge xor_block_done
    
    movb (%rdi,%r8), %al
    xorb (%rsi,%rax), %al
    movb %al, (%rcx,%r8)
    
    inc %r8
    inc %rax
    jmp xor_byte_loop
    
xor_block_done:
    # Move to next block
    inc %r9
    jmp xor_loop
    
xor_done:
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