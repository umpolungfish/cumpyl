#!/usr/bin/env python3
"""
Unit tests for the CA Engine module (ca_engine.py).
"""

import sys
import os

# Add the ca_packer directory to the path so we can import modules from it
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ca_packer'))

import unittest
import ca_engine

class TestCAEngine(unittest.TestCase):

    def test_generate_mask_basic(self):
        """Test basic mask generation with fixed inputs."""
        key_material = b"test_key_1234567890123456789012" # 32 bytes key material
        block_index = 1
        mask_length = 32 # 32 bytes = 256 bits

        mask1 = ca_engine.generate_mask(key_material, block_index, mask_length)
        self.assertEqual(len(mask1), mask_length)

        # Generate again with same inputs, should be identical
        mask2 = ca_engine.generate_mask(key_material, block_index, mask_length)
        self.assertEqual(mask1, mask2)

    def test_generate_mask_different_index(self):
        """Test that different block indices produce different masks."""
        key_material = b"another_test_key_098765432109876543210" # 32 bytes
        mask_length = 16 # 16 bytes

        mask1 = ca_engine.generate_mask(key_material, 0, mask_length)
        mask2 = ca_engine.generate_mask(key_material, 1, mask_length)
        mask3 = ca_engine.generate_mask(key_material, 100, mask_length)

        self.assertEqual(len(mask1), mask_length)
        self.assertEqual(len(mask2), mask_length)
        self.assertEqual(len(mask3), mask_length)

        # All masks should be different
        self.assertNotEqual(mask1, mask2)
        self.assertNotEqual(mask1, mask3)
        self.assertNotEqual(mask2, mask3)

    def test_generate_mask_different_key(self):
        """Test that different keys produce different masks."""
        block_index = 5
        mask_length = 8 # 8 bytes

        key1 = b"different_key_material_12345678" # 32 bytes
        key2 = b"different_key_material_87654321" # 32 bytes

        mask1 = ca_engine.generate_mask(key1, block_index, mask_length)
        mask2 = ca_engine.generate_mask(key2, block_index, mask_length)

        self.assertEqual(len(mask1), mask_length)
        self.assertEqual(len(mask2), mask_length)
        self.assertNotEqual(mask1, mask2)

    def test_generate_mask_length_boundary(self):
        """Test mask generation at the maximum supported length."""
        key_material = b"boundary_test_key_material_123456789012" # 32 bytes
        block_index = 0
        max_length = ca_engine.GRID_SIZE // 8 # 32 bytes for a 256-bit grid

        mask = ca_engine.generate_mask(key_material, block_index, max_length)
        self.assertEqual(len(mask), max_length)

    def test_generate_mask_length_too_large(self):
        """Test that requesting a mask larger than the grid size raises an error."""
        key_material = b"too_large_test_key_material_12345678901" # 32 bytes
        block_index = 0
        invalid_length = (ca_engine.GRID_SIZE // 8) + 1 # One byte too large

        with self.assertRaises(ValueError):
            ca_engine.generate_mask(key_material, block_index, invalid_length)

if __name__ == '__main__':
    unittest.main()
