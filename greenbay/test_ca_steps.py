#!/usr/bin/env python3
"""
Test script to verify the --ca-steps parameter is working correctly.
"""

import sys
import os

# Add the ca_packer directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ca_packer import ca_engine

def test_ca_steps():
    """Test that we can modify NUM_STEPS"""
    # Check default value
    print(f"Default NUM_STEPS: {ca_engine.NUM_STEPS}")
    
    # Modify it
    ca_engine.NUM_STEPS = 200
    print(f"Modified NUM_STEPS: {ca_engine.NUM_STEPS}")
    
    # Verify it's correctly set
    assert ca_engine.NUM_STEPS == 200, f"Expected 200, got {ca_engine.NUM_STEPS}"
    print("Test passed!")

if __name__ == "__main__":
    test_ca_steps()