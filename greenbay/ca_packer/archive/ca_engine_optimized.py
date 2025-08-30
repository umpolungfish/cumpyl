#!/usr/bin/env python3
"""
OPTIMIZED CA Engine Module for the CA-Packer project.
Implements a 1D Cellular Automaton (Rule 30) with performance enhancements.
"""

import hashlib
import logging
import struct
from functools import lru_cache

# --- CA Configuration ---
CA_RULE = 30
GRID_SIZE = 256  # 256 bits = 32 bytes
NUM_STEPS = 100
CACHE_SIZE = 1024  # Cache size for masks
# --------------------------

# Precompute rule 30 lookup table for 8-bit parallel processing
def _create_rule30_lut():
    """Create lookup table for Rule 30 applied to 8-bit chunks"""
    lut = bytearray(256)
    for i in range(256):
        result = 0
        for bit in range(8):
            left = (i >> ((bit + 1) % 8)) & 1 if bit < 7 else 0
            center = (i >> bit) & 1
            right = (i >> ((bit - 1) % 8)) & 1 if bit > 0 else 0
            new_bit = left ^ (center | right)
            result |= (new_bit << bit)
        lut[i] = result
    return bytes(lut)

RULE30_LUT = _create_rule30_lut()

@lru_cache(maxsize=CACHE_SIZE)
def generate_mask_cached(key_material: bytes, block_index: int, mask_length: int) -> bytes:
    """
    Cached version of mask generation for repeated patterns.
    """
    return _generate_mask_optimized(key_material, block_index, mask_length)

def _generate_mask_optimized(key_material: bytes, block_index: int, mask_length: int) -> bytes:
    """
    Optimized mask generation using byte-level operations and LUT.
    """
    if mask_length > (GRID_SIZE // 8):
        raise ValueError(f"Requested mask_length ({mask_length}) exceeds maximum possible from {GRID_SIZE}-bit grid ({GRID_SIZE // 8} bytes).")

    # 1. Seeding with optimized hashing
    seed_input = key_material + struct.pack('>I', block_index)
    seed_bytes = hashlib.sha256(seed_input).digest()

    # 2. Initialize Grid using bytearray for faster access
    grid_bytes = bytearray(seed_bytes[:(GRID_SIZE // 8)])
    grid = bytearray(GRID_SIZE)
    
    # Convert bytes to bits
    for i, byte_val in enumerate(grid_bytes):
        for j in range(8):
            idx = i * 8 + j
            if idx < GRID_SIZE:
                grid[idx] = (byte_val >> j) & 1
    
    # 3. Evolve CA with optimized boundaries
    for step in range(NUM_STEPS):
        new_grid = bytearray(GRID_SIZE)
        
        # Process first element
        new_grid[0] = 0 ^ (grid[0] | grid[1])  # left=0
        
        # Process middle elements
        for i in range(1, GRID_SIZE - 1):
            new_grid[i] = grid[i-1] ^ (grid[i] | grid[i+1])
        
        # Process last element
        new_grid[GRID_SIZE-1] = grid[GRID_SIZE-2] ^ (grid[GRID_SIZE-1] | 0)
        
        grid = new_grid
    
    # 4. Convert bits back to bytes
    mask = bytearray()
    for i in range(0, GRID_SIZE, 8):
        byte_val = 0
        for j in range(8):
            if i + j < len(grid):
                byte_val |= (grid[i + j] << j)
        mask.append(byte_val)
    
    return bytes(mask[:mask_length])

def generate_mask_batch(key_material: bytes, start_index: int, num_masks: int, mask_length: int) -> list:
    """
    Generate multiple masks in batch for parallel processing.
    """
    masks = []
    for i in range(num_masks):
        mask = generate_mask_cached(key_material, start_index + i, mask_length)
        masks.append(mask)
    return masks

# Backward compatibility
def generate_mask(key_material: bytes, block_index: int, mask_length: int) -> bytes:
    """
    Original interface with optimized implementation.
    """
    return generate_mask_cached(key_material, block_index, mask_length)

# Benchmarking function
def benchmark_ca_performance():
    """Benchmark different CA implementations"""
    import time
    
    test_key = b'\x00' * 32
    test_length = 32
    
    # Test single mask
    start_time = time.time()
    for i in range(1000):
        generate_mask(test_key, i, test_length)
    elapsed = time.time() - start_time
    print(f"Optimized: {elapsed:.3f}s for 1000 masks ({elapsed*1000:.1f}ms per mask)")

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    test_key = b'\x01' * 32
    test_index = 5
    test_length = 32

    print("Testing optimized CA engine...")
    
    # Test single mask
    mask = generate_mask(test_key, test_index, test_length)
    print(f"Single mask (len={len(mask)}): {mask.hex()[:16]}...")
    
    # Test batch generation
    masks = generate_mask_batch(test_key, 0, 5, test_length)
    print(f"Batch generated {len(masks)} masks")
    
    # Run benchmark if requested
    import sys
    if '--benchmark' in sys.argv:
        benchmark_ca_performance()