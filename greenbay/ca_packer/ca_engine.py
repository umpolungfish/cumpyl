#!/usr/bin/env python3
"""
CA Engine Module for the CA-Packer project.
Implements a 1D Cellular Automaton (Rule 30) to function as a PRNG for mask generation.
"""

import hashlib
import logging

# Allow importing ca_engine for NUM_STEPS constant
NUM_STEPS = 100

# --- CA Configuration ---
CA_RULE = 30
GRID_SIZE = 256 # Number of cells, must be even for byte alignment (256 bits = 32 bytes)
NUM_STEPS = 100
# --------------------------

def _apply_rule_30(left: int, center: int, right: int) -> int:
    """
    Applies Rule 30 to a triplet of cells.
    Rule 30: new_center = left XOR (center OR right)
    Assumes inputs are 0 or 1.
    """
    return left ^ (center | right)

def generate_mask(key_material: bytes, block_index: int, mask_length: int) -> bytes:
    """
    Generates a pseudo-random mask using a 1D Cellular Automaton (Rule 30).

    Args:
        key_material (bytes): The primary encryption key.
        block_index (int): The index of the data block being processed.
        mask_length (int): The desired length of the mask in bytes.

    Returns:
        bytes: The generated mask of length `mask_length`.
    """
    if mask_length > (GRID_SIZE // 8):
        raise ValueError(f"Requested mask_length ({mask_length}) exceeds maximum possible from {GRID_SIZE}-bit grid ({GRID_SIZE // 8} bytes).")

    # 1. Seeding
    seed_input = key_material + block_index.to_bytes(4, byteorder='big')
    # Use a hash function (e.g., SHA-256) to derive a fixed-length seed
    hash_obj = hashlib.sha256(seed_input)
    seed_bytes = hash_obj.digest() # 32 bytes from SHA-256

    # 2. Initialize Grid
    # Use the first (GRID_SIZE // 8) bytes of the hash for the initial grid state
    initial_grid_bytes = seed_bytes[:(GRID_SIZE // 8)]
    # Convert bytes to a list of integers (0 or 1) representing the grid
    grid = []
    for byte_val in initial_grid_bytes:
        for i in range(8): # Process each bit in the byte
            grid.append((byte_val >> i) & 1)

    # Ensure grid is exactly GRID_SIZE
    if len(grid) != GRID_SIZE:
         logging.error(f"Grid initialization failed, size is {len(grid)}, expected {GRID_SIZE}")
         raise RuntimeError("Failed to initialize CA grid correctly.")

    # 3. Evolve CA
    for step in range(NUM_STEPS):
        new_grid = [0] * GRID_SIZE
        for i in range(GRID_SIZE):
            # Handle boundary conditions (fixed, edges are 0)
            left = grid[i - 1] if i > 0 else 0
            center = grid[i]
            right = grid[i + 1] if i < GRID_SIZE - 1 else 0

            new_grid[i] = _apply_rule_30(left, center, right)
        grid = new_grid

    # 4. Extract Mask
    # Convert the final grid state back to bytes
    mask_bits = grid[:mask_length * 8] # Take only the bits needed for the mask
    mask_bytes = bytearray()
    for i in range(0, len(mask_bits), 8):
        byte_val = 0
        # Process 8 bits to form a byte (LSB first within the byte, standard convention)
        for j in range(8):
            if i + j < len(mask_bits) and mask_bits[i + j]:
                byte_val |= (1 << j)
        mask_bytes.append(byte_val)

    return bytes(mask_bytes)

# Example usage (if run as a script)
if __name__ == "__main__":
    import os
    # Configure logging
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    test_key = os.urandom(32) # 256-bit key
    test_index = 5
    test_length = 32 # 32 bytes = 256 bits

    print(f"Generating mask for block index {test_index} with key {test_key.hex()[:16]}...")
    mask = generate_mask(test_key, test_index, test_length)
    print(f"Generated mask (len={len(mask)}): {mask.hex()}")
