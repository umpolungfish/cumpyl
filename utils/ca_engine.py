"""
Cellular Automata engine for binary packing
Implements cellular automata rules for transforming binary data.
"""

import random
from typing import List, Tuple
import logging

# Default number of steps for CA processing
NUM_STEPS = 100

logger = logging.getLogger(__name__)

def initialize_ca_grid(size: int) -> List[int]:
    """
    Initialize a cellular automata grid with random values.
    
    Args:
        size: Size of the grid to initialize
        
    Returns:
        List of integers (0 or 1) representing the initial CA state
    """
    return [random.randint(0, 1) for _ in range(size)]

def apply_rule_30(left: int, center: int, right: int) -> int:
    """
    Apply Rule 30 of cellular automata.
    Rule 30 is a complex, aperiodic, chaotic elementary cellular automaton.
    
    Args:
        left: Left neighbor cell value
        center: Center cell value  
        right: Right neighbor cell value
        
    Returns:
        New value for the center cell based on Rule 30
    """
    # Rule 30 truth table:
    # 111 -> 0
    # 110 -> 0
    # 101 -> 0
    # 100 -> 1
    # 011 -> 1
    # 010 -> 1
    # 001 -> 1
    # 000 -> 0
    
    rule_30_map = {
        (1, 1, 1): 0,
        (1, 1, 0): 0,
        (1, 0, 1): 0,
        (1, 0, 0): 1,
        (0, 1, 1): 1,
        (0, 1, 0): 1,
        (0, 0, 1): 1,
        (0, 0, 0): 0,
    }
    
    return rule_30_map.get((left, center, right), 0)

def apply_rule_90(left: int, center: int, right: int) -> int:
    """
    Apply Rule 90 of cellular automata (XOR rule).
    
    Args:
        left: Left neighbor cell value
        center: Center cell value  
        right: Right neighbor cell value
        
    Returns:
        New value for the center cell based on Rule 90
    """
    # Rule 90: XOR of left and right neighbors
    return left ^ right

def evolve_ca_step(current_grid: List[int], rule_function=apply_rule_30) -> List[int]:
    """
    Evolve the CA grid by one step using the specified rule.
    
    Args:
        current_grid: Current state of the CA grid
        rule_function: Function to apply for each cell evolution
        
    Returns:
        New state of the CA grid after one evolution step
    """
    if len(current_grid) < 3:
        return current_grid[:]
    
    new_grid = [0] * len(current_grid)
    
    # Handle edge cells specially
    new_grid[0] = rule_function(0, current_grid[0], current_grid[1])
    new_grid[-1] = rule_function(current_grid[-2], current_grid[-1], 0)
    
    # Process middle cells
    for i in range(1, len(current_grid) - 1):
        new_grid[i] = rule_function(
            current_grid[i-1],  # left
            current_grid[i],    # center
            current_grid[i+1]   # right
        )
    
    return new_grid

def evolve_ca_multiple_steps(initial_grid: List[int], num_steps: int, rule_function=apply_rule_30) -> List[List[int]]:
    """
    Evolve the CA grid for multiple steps.
    
    Args:
        initial_grid: Initial state of the CA grid
        num_steps: Number of evolution steps to perform
        rule_function: Function to apply for each cell evolution
        
    Returns:
        List of all grid states after each evolution step
    """
    grids = [initial_grid[:]]  # Start with a copy of initial grid
    
    current_grid = initial_grid[:]
    for step in range(num_steps):
        current_grid = evolve_ca_step(current_grid, rule_function)
        grids.append(current_grid)
    
    return grids

def generate_ca_mask(size: int, num_steps: int = None, rule_function=apply_rule_30) -> bytes:
    """
    Generate a cellular automata-based mask of specified size.
    This mask can be used for XOR-based obfuscation of binary data.
    
    Args:
        size: Size of the mask to generate (in bytes)
        num_steps: Number of CA evolution steps to use (default: NUM_STEPS)
        rule_function: CA rule to use for evolution
        
    Returns:
        Bytes object containing the generated mask
    """
    if num_steps is None:
        num_steps = NUM_STEPS
    
    # Create a sufficiently large grid to generate the required mask
    grid_size = size * 8  # Convert bytes to bits
    if grid_size < 100:  # Ensure minimum size for interesting patterns
        grid_size = 100
    
    # Initialize grid with some entropy from the size parameter
    initial_grid = initialize_ca_grid(grid_size)
    
    # Set a few bits based on the size to ensure different sizes produce different masks
    for i in range(min(32, len(initial_grid))):
        initial_grid[i] = (size >> i) & 1
    
    # Evolve the grid for the specified number of steps
    evolved_grids = evolve_ca_multiple_steps(initial_grid, num_steps, rule_function)
    
    # Extract the final state and convert to bytes
    final_state = evolved_grids[-1]
    
    # Convert bits to bytes
    mask_bytes = bytearray()
    for i in range(0, len(final_state), 8):
        byte = 0
        for bit_idx in range(8):
            if i + bit_idx < len(final_state):
                byte |= (final_state[i + bit_idx] << (7 - bit_idx))
        mask_bytes.append(byte)
    
    return bytes(mask_bytes[:size])  # Return only the requested size

def mutate_binary_with_ca(binary_data: bytes, num_steps: int = None, rule_function=apply_rule_30) -> bytes:
    """
    Apply cellular automata transformation to binary data.
    
    Args:
        binary_data: Input binary data to transform
        num_steps: Number of CA evolution steps to use (default: NUM_STEPS)
        rule_function: CA rule to use for evolution
        
    Returns:
        Transformed binary data
    """
    if num_steps is None:
        num_steps = NUM_STEPS
    
    # Generate a CA mask of the same size as the binary data
    mask = generate_ca_mask(len(binary_data), num_steps, rule_function)
    
    # XOR the binary data with the CA mask for obfuscation
    transformed_data = bytearray()
    for i, byte in enumerate(binary_data):
        transformed_data.append(byte ^ mask[i % len(mask)])
    
    logger.debug(f"Applied CA transformation with {num_steps} steps, rule {rule_function.__name__}")
    
    return bytes(transformed_data)

def validate_ca_grid(grid: List[int]) -> bool:
    """
    Validate that a CA grid contains only binary values (0 or 1).
    
    Args:
        grid: CA grid to validate
        
    Returns:
        True if grid is valid, False otherwise
    """
    if not grid:
        return True
    
    for cell in grid:
        if cell not in (0, 1):
            return False
    
    return True

def evolve_ca_with_boundary_conditions(current_grid: List[int], rule_function=apply_rule_30, 
                                    left_boundary: int = 0, right_boundary: int = 0) -> List[int]:
    """
    Evolve the CA grid by one step with specified boundary conditions.
    
    Args:
        current_grid: Current state of the CA grid
        rule_function: Function to apply for each cell evolution
        left_boundary: Value for the left boundary (0 or 1)
        right_boundary: Value for the right boundary (0 or 1)
        
    Returns:
        New state of the CA grid after one evolution step
    """
    if len(current_grid) < 3:
        return current_grid[:]
    
    new_grid = [0] * len(current_grid)
    
    # Apply boundary conditions
    new_grid[0] = rule_function(left_boundary, current_grid[0], current_grid[1])
    new_grid[-1] = rule_function(current_grid[-2], current_grid[-1], right_boundary)
    
    # Process middle cells
    for i in range(1, len(current_grid) - 1):
        new_grid[i] = rule_function(
            current_grid[i-1],  # left
            current_grid[i],    # center
            current_grid[i+1]   # right
        )
    
    return new_grid

def generate_pseudorandom_sequence(ca_grid: List[int], length: int, num_steps: int = None) -> List[int]:
    """
    Generate a pseudorandom sequence from CA evolution.
    
    Args:
        ca_grid: Initial CA grid state
        length: Desired length of output sequence
        num_steps: Number of evolution steps (default: NUM_STEPS)
        
    Returns:
        List of integers (0 or 1) forming the pseudorandom sequence
    """
    if num_steps is None:
        num_steps = NUM_STEPS
        
    # Evolve the CA for the specified number of steps
    evolved_grids = evolve_ca_multiple_steps(ca_grid, num_steps)
    
    # Use the final state to generate pseudorandom sequence
    sequence = []
    final_state = evolved_grids[-1]
    
    # Use a simple scrambling approach to generate more output
    for step in range(num_steps):
        for bit in final_state:
            if len(sequence) >= length:
                break
            sequence.append(bit)
        # Scramble the state slightly for next iteration
        final_state = evolve_ca_step(final_state)
    
    return sequence[:length]

def create_ca_based_xor_key(seed_data: bytes, size: int, num_steps: int = None) -> bytes:
    """
    Create an XOR key based on CA evolution derived from seed data.
    
    Args:
        seed_data: Initial seed data to influence CA evolution
        size: Size of the XOR key to generate
        num_steps: Number of CA evolution steps (default: NUM_STEPS)
        
    Returns:
        Bytes object containing the XOR key
    """
    if num_steps is None:
        num_steps = NUM_STEPS
    
    # Create initial grid based on seed data
    initial_size = max(len(seed_data) * 8, 100)  # At least 100 bits
    initial_grid = initialize_ca_grid(initial_size)
    
    # Seed the grid with the input data
    for i, byte in enumerate(seed_data):
        for bit_pos in range(8):
            grid_idx = (i * 8 + bit_pos) % len(initial_grid)
            initial_grid[grid_idx] = (byte >> (7 - bit_pos)) & 1
    
    # Evolve the CA and generate the key
    final_grid = evolve_ca_multiple_steps(initial_grid, num_steps)[-1]
    
    # Convert grid to bytes
    key_bytes = bytearray()
    for i in range(0, len(final_grid), 8):
        byte = 0
        for bit_idx in range(8):
            if i + bit_idx < len(final_grid):
                byte |= (final_grid[i + bit_idx] << (7 - bit_idx))
        key_bytes.append(byte)
    
    return bytes(key_bytes[:size])

if __name__ == "__main__":
    # Test the CA engine
    print("Testing CA engine...")
    
    # Test basic functionality
    initial = initialize_ca_grid(20)
    print(f"Initial grid: {initial[:10]}...")
    
    evolved = evolve_ca_step(initial)
    print(f"Evolved grid: {evolved[:10]}...")
    
    # Test mask generation
    mask = generate_ca_mask(16, 50)
    print(f"Generated mask (16 bytes): {mask.hex()}")
    
    # Test binary mutation
    test_data = b"Hello, CA-based packer!"
    mutated = mutate_binary_with_ca(test_data, 25)
    print(f"Original: {test_data}")
    print(f"Mutated:  {mutated}")
    print("CA engine test completed.")